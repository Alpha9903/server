require("dotenv").config({ path: "key.env" });
const express = require("express");
const { readFile, writeFile } = require("fs").promises;
const axios = require("axios");
const path = require("path");
const Redis = require("ioredis");
const redisclient = new Redis("redis://127.0.0.1:6379"); // Directly hardcoding the Redis URL
const mysql = require("mysql2/promise");
const cors = require("cors");
const WebSocket = require("ws");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const Stripe = require("stripe");

const app = express();
const server = require("http").createServer(app);
const wss = new WebSocket.Server({ server });
const PORT = process.env.PORT || 3000;
const questionsFile = path.join(__dirname, "public", "questions.json");
const SCRAPE_URL = "https://floralwhite-wallaby-276579.hostingersite.com/";
const COMPANY_NAME = "Jain Estates"; // Updated to Jain Estates

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";

const genAI = new GoogleGenerativeAI(process.env.GOOGLE_API_KEY);
const geminiModel = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

if (!process.env.GOOGLE_API_KEY || !process.env.STRIPE_SECRET_KEY) {
    console.error("ERROR: Missing GOOGLE_API_KEY or STRIPE_SECRET_KEY in key.env");
    process.exit(1);
}

const DB_CONFIG = {
    host: "localhost",
    user: "root",
    password: "12345",
    database: "bot_database",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
};

const db = mysql.createPool(DB_CONFIG);
console.log("Connected to MySQL database!");

// Rate limiter for Gemini API requests
const geminiRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 15,
    message: "Too many requests to Gemini API. Please wait a minute and try again.",
});

app.use(express.static("public"));
app.use(express.json({ limit: '10mb' }));
app.use(cors());

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET || "your_session_secret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// Middleware to verify JWT
const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid token" });
        req.user = user;
        next();
    });
};

redisclient.on("connect", () => {
    console.log("✅ Connected to Redis successfully!");
});

redisclient.on("error", (err) => {
    console.error("❌ Redis Error:", err);
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

app.get("/signup", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "signup.html"));
});

app.get("/chat", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get("/dashboard", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// Signup Endpoint
app.post("/signup", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Username and password are required" });
    }

    try {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        const query = "INSERT INTO users (username, password) VALUES (?, ?)";
        await db.execute(query, [username, hashedPassword]);

        // Initialize company settings and subscription
        await db.execute(
            "INSERT INTO company_settings (company_id) VALUES (?)",
            [username]
        );
        await db.execute(
            "INSERT INTO subscriptions (company_id, plan) VALUES (?, 'freemium')",
            [username]
        );

        res.status(201).json({ message: "User created successfully" });
    } catch (err) {
        if (err.code === "ER_DUP_ENTRY") {
            return res.status(400).json({ message: "Username already exists" });
        }
        console.error("Error creating user:", err);
        res.status(500).json({ message: "Error creating user" });
    }
});

// Login Endpoint
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Username and password are required" });
    }

    try {
        const query = "SELECT * FROM users WHERE username = ?";
        const [results] = await db.execute(query, [username]);

        if (results.length === 0) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        const user = results[0];
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ message: "Invalid username or password" });
        }

        const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: "1h" });
        req.session.user = user;
        res.status(200).json({ message: "Login successful", token });
    } catch (err) {
        console.error("Error logging in:", err);
        res.status(500).json({ message: "Error logging in" });
    }
});

// Fetch user contact info
app.get("/api/user-contact/:userId", async (req, res) => {
    const { userId } = req.params;
    try {
        const [userContact] = await db.execute(
            "SELECT name FROM user_contacts WHERE user_id = ?",
            [userId]
        );
        if (userContact.length === 0) {
            return res.status(404).json({ error: "User contact not found" });
        }
        res.json({ name: userContact[0].name });
    } catch (err) {
        console.error("Error fetching user contact:", err);
        res.status(500).json({ error: "Error fetching user contact" });
    }
});

// Function to convert latitude and longitude to place name
async function getPlaceName(latitude, longitude) {
    try {
        const response = await axios.get(`https://nominatim.openstreetmap.org/reverse`, {
            params: { lat: latitude, lon: longitude, format: 'json' },
            headers: { 'User-Agent': 'CustomMadeBot/1.0 (kaushiketan@gmail.com)' },
            timeout: 5000,
        });
        return response.data.display_name || "Unknown location";
    } catch (err) {
        console.error("Error fetching place name:", err.message);
        return "Unknown location";
    }
}

// Function to store location data in database
async function storeLocationData(user_id, product_id, latitude, longitude, place_name) {
    try {
        const query = `
            INSERT INTO location_logs (user_id, product_id, latitude, longitude, place_name)
            VALUES (?, ?, ?, ?, ?)
        `;
        const [result] = await db.execute(query, [user_id, product_id, latitude, longitude, place_name]);
        console.log(`Location data stored for user ${user_id}, product ${product_id}`);
        return result.insertId;
    } catch (err) {
        console.error("Error storing location data:", err);
        throw err;
    }
}

async function ensureQuestionsFile() {
    try {
        await readFile(questionsFile, "utf-8");
    } catch (error) {
        if (error.code === "ENOENT") {
            await writeFile(questionsFile, "[]");
        } else {
            console.error("Error ensuring questions.json:", error);
        }
    }
}
ensureQuestionsFile();

async function saveChatToDB(user_id, question, answer) {
    try {
        const query = `INSERT INTO chat_logs (user_id, message, response, timestamp) VALUES (?, ?, ?, NOW())`;
        const [result] = await db.execute(query, [user_id, question, answer]);
        console.log(`Chat saved in MySQL! Rows affected: ${result.affectedRows}`);
    } catch (err) {
        console.error("Error saving chat in MySQL:", err.message);
    }
}

async function registerUser(user_id) {
    try {
        console.log(`Registering user: ${user_id}`);
        const [rows] = await db.execute("SELECT * FROM users WHERE username = ?", [user_id]);
        if (rows.length === 0) {
            const saltRounds = 10;
            const dummyPassword = await bcrypt.hash("default123", saltRounds);
            await db.execute("INSERT INTO users (username, password) VALUES (?, ?)", [user_id, dummyPassword]);
            await db.execute("INSERT INTO company_settings (company_id) VALUES (?)", [user_id]);
            await db.execute("INSERT INTO subscriptions (company_id, plan) VALUES (?, 'freemium')", [user_id]);
            console.log(`New user registered: ${user_id}`);
        } else {
            console.log(`User ${user_id} already exists`);
        }
    } catch (err) {
        console.error("Error registering user:", err);
        throw err;
    }
}

async function storeInDB(source, content) {
    try {
        const query = "INSERT INTO knowledge_base (source, content) VALUES (?, ?)";
        await db.execute(query, [source, content]);
        console.log(`Data from ${source} stored successfully.`);
    } catch (err) {
        console.error("Database error:", err);
    }
}

async function scrapeWebsite(url) {
    try {
        const response = await axios.get(url, { timeout: 10000 });
        const text = response.data.match(/<p[^>]*>(.*?)<\/p>/gi)
            ?.map(p => p.replace(/<[^>]*>/g, ""))
            .join(" ") || "";
        if (text.trim()) {
            const limitedText = text.substring(0, 500);
            await storeInDB(url, limitedText);
            return limitedText;
        }
        return "No meaningful content found on the page.";
    } catch (err) {
        console.error("Failed to fetch URL:", err.message);
        return `Error: ${err.message}`;
    }
}

async function fetchFromKB(query) {
    try {
        const [rows] = await db.execute(
            "SELECT content FROM knowledge_base WHERE content LIKE ? LIMIT 1",
            [`%${query}%`]
        );
        return rows.length > 0 ? rows[0].content.substring(0, 500) : null;
    } catch (err) {
        console.error("Error querying knowledge base:", err);
        return null;
    }
}

async function fetchRelevantKBContent(query) {
    try {
        const [rows] = await db.execute(
            "SELECT content FROM knowledge_base WHERE content LIKE ? LIMIT 1",
            [`%${query}%`]
        );
        return rows.length > 0 ? rows[0].content.substring(0, 500) : "";
    } catch (err) {
        console.error("Error fetching relevant KB content:", err);
        return "";
    }
}

function estimateTokens(text) {
    return Math.ceil(text.length / 4);
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function getTimeBasedGreeting() {
    const currentHour = new Date().getHours();
    if (currentHour < 12) return "Good Morning";
    if (currentHour < 17) return "Good Afternoon";
    return "Good Evening";
}

function fixCommonTypos(response) {
    return response.replace(/asshait/gi, "assist");
}

function formatResponse(response) {
    let formatted = response;
    formatted = formatted.replace(/\*([^*]+):\*/g, '\n*$1:*\n');
    formatted = formatted.replace(/\.(\s+)/g, '.\n$1');
    formatted = formatted.replace(/\n\s*\n/g, '\n\n');
    return formatted.trim();
}

async function getAvailableSlots(dateString) {
    try {
        const selectedDate = new Date(dateString);
        const dayStart = new Date(selectedDate.setHours(0, 0, 0, 0));
        const dayEnd = new Date(selectedDate.setHours(23, 59, 59, 999));

        const query = `
            SELECT time 
            FROM appointments 
            WHERE time BETWEEN ? AND ? 
            AND status = 'booked'
        `;
        const [bookedSlots] = await db.execute(query, [dayStart, dayEnd]);

        const possibleSlots = [];
        for (let hour = 9; hour <= 17; hour++) {
            const slotTime = new Date(selectedDate);
            slotTime.setHours(hour, 0, 0, 0);
            possibleSlots.push(slotTime);
        }

        const bookedTimes = bookedSlots.map(slot => new Date(slot.time).getTime());
        const availableSlots = possibleSlots.filter(slot => !bookedTimes.includes(slot.getTime()));
        return availableSlots.map(slot => slot.toISOString().replace('T', ' ').substring(0, 16));
    } catch (err) {
        console.error("Error getting available slots:", err);
        throw err;
    }
}

async function storeContactInfo(user_id, name, email, number) {
    try {
        const query = `
            INSERT INTO user_contacts (user_id, name, email, number)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE name = ?, email = ?, number = ?
        `;
        await db.execute(query, [user_id, name, email, number, name, email, number]);
        console.log(`Contact info saved for user ${user_id}`);
    } catch (err) {
        console.error("Error saving contact info:", err);
    }
}

async function storeAppointment(user_id, time, purpose) {
    try {
        const query = `
            INSERT INTO appointments (user_id, time, address, purpose, status)
            VALUES (?, ?, ?, ?, 'booked')
        `;
        const [result] = await db.execute(query, [user_id, time, "Jain Estates Office", purpose]);
        console.log(`Appointment booked for user ${user_id}, ID: ${result.insertId}`);
        return result.insertId;
    } catch (err) {
        console.error("Error saving appointment:", err);
        throw err;
    }
}

async function cancelAppointment(appointment_id, user_id) {
    try {
        const query = `
            UPDATE appointments 
            SET status = 'cancelled' 
            WHERE appointment_id = ? AND user_id = ? AND status = 'booked'
        `;
        const [result] = await db.execute(query, [appointment_id, user_id]);
        return result.affectedRows > 0;
    } catch (err) {
        console.error("Error cancelling appointment:", err);
        throw err;
    }
}

async function fetchAppointmentHistory(user_id) {
    try {
        const query = `
            SELECT appointment_id, time, address, purpose, status 
            FROM appointments 
            WHERE user_id = ? 
            ORDER BY time DESC
        `;
        const [rows] = await db.execute(query, [user_id]);
        return rows;
    } catch (err) {
        console.error("Error fetching appointment history:", err);
        throw err;
    }
}

async function fetchTicketHistory(user_id) {
    try {
        const query = `
            SELECT ticket_id, issue, status, created_at, closed_at 
            FROM tickets 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        `;
        const [rows] = await db.execute(query, [user_id]);
        return rows;
    } catch (err) {
        console.error("Error fetching ticket history:", err);
        throw err;
    }
}

async function raiseTicket(user_id, issue) {
    try {
        const query = `
            INSERT INTO tickets (user_id, issue, status)
            VALUES (?, ?, 'open')
        `;
        const [result] = await db.execute(query, [user_id, issue]);
        return result.insertId;
    } catch (err) {
        console.error("Error raising ticket:", err);
        throw err;
    }
}

async function closeTicket(ticket_id, user_id) {
    try {
        const query = `
            UPDATE tickets 
            SET status = 'closed', closed_at = NOW()
            WHERE ticket_id = ? AND user_id = ? AND status = 'open'
        `;
        const [result] = await db.execute(query, [ticket_id, user_id]);
        return result.affectedRows > 0;
    } catch (err) {
        console.error("Error closing ticket:", err);
        throw err;
    }
}

function wantsToShareContact(message) {
    const lowerMessage = message.toLowerCase();
    return (
        lowerMessage.includes("take my contact") ||
        lowerMessage.includes("share my contact") ||
        lowerMessage.includes("add my contact") ||
        lowerMessage.includes("update my contact") ||
        lowerMessage.includes("give my contact") ||
        lowerMessage.includes("changed my mind") ||
        lowerMessage.includes("now take my contact") ||
        lowerMessage.includes("i want to share my contact") ||
        lowerMessage.includes("store my contact")
    );
}

function wantsToBookAppointment(message) {
    const lowerMessage = message.toLowerCase();
    const hasAppointmentKeyword = lowerMessage.includes("appointment") || lowerMessage.includes("meet an executive");
    const hasBookingIntent = lowerMessage.includes("book") || lowerMessage.includes("schedule") || lowerMessage.includes("want to meet") || lowerMessage.includes("set up");
    const isQuestion = lowerMessage.includes("?") && (lowerMessage.includes("can i") || lowerMessage.includes("how to"));
    return (hasAppointmentKeyword && hasBookingIntent) || (hasAppointmentKeyword && isQuestion);
}

function wantsToCancelAppointment(message) {
    const lowerMessage = message.toLowerCase();
    return lowerMessage.includes("cancel") && (lowerMessage.includes("appointment") || lowerMessage.includes("meeting"));
}

function wantsToSeeAppointmentHistory(message) {
    const lowerMessage = message.toLowerCase();
    return (
        lowerMessage.includes("history") ||
        lowerMessage.includes("my appointments") ||
        lowerMessage.includes("show appointments") ||
        lowerMessage.includes("list appointments")
    );
}

function wantsToRaiseTicket(message) {
    const lowerMessage = message.toLowerCase();
    return (
        lowerMessage.includes("issue") ||
        lowerMessage.includes("problem") ||
        lowerMessage.includes("complaint") ||
        lowerMessage.includes("query") ||
        lowerMessage.includes("help") ||
        lowerMessage.includes("support") ||
        lowerMessage.includes("ticket")
    ) && !lowerMessage.includes("status") && !lowerMessage.includes("history");
}

function wantsToSeeTicketHistory(message) {
    const lowerMessage = message.toLowerCase();
    return (
        lowerMessage.includes("ticket status") ||
        lowerMessage.includes("ticket history") ||
        lowerMessage.includes("show tickets") ||
        lowerMessage.includes("list tickets")
    );
}

function isUserSatisfied(message) {
    const lowerMessage = message.toLowerCase();
    return (
        lowerMessage.includes("yes") ||
        lowerMessage.includes("satisfied") ||
        lowerMessage.includes("resolved") ||
        lowerMessage.includes("fixed") ||
        lowerMessage.includes("thank you") ||
        lowerMessage.includes("thanks")
    );
}

function wantsToCancelProcess(message) {
    const lowerMessage = message.toLowerCase();
    return (
        lowerMessage.includes("don't want") ||
        lowerMessage.includes("do not want") ||
        lowerMessage.includes("cancel") ||
        lowerMessage.includes("stop") ||
        lowerMessage.includes("no longer") ||
        lowerMessage.includes("not interested") ||
        lowerMessage.includes("changed my mind") ||
        lowerMessage.includes("never mind") ||
        lowerMessage.includes("forget it")
    ) && (
        lowerMessage.includes("appointment") ||
        lowerMessage.includes("ticket") ||
        lowerMessage.includes("book") ||
        lowerMessage.includes("raise") ||
        lowerMessage.includes("schedule") ||
        lowerMessage.includes("issue")
    );
}

async function isContactInfoMissing(user_id) {
    try {
        console.log(`Checking contact info for user: ${user_id}`);
        const [userContact] = await db.execute("SELECT * FROM user_contacts WHERE user_id = ?", [user_id]);
        if (userContact.length === 0) {
            console.log(`No contact info found for user: ${user_id}`);
            return true;
        }
        const contact = userContact[0];
        const missing = !contact.email || !contact.number;
        console.log(`Contact info missing for user ${user_id}: ${missing}`);
        return missing;
    } catch (err) {
        console.error("Error checking contact info:", err);
        throw err;
    }
}

async function getUserState(user_id) {
    try {
        const stateData = await redisclient.get(`user_state:${user_id}`);
        return stateData ? JSON.parse(stateData) : { state: "initial", data: {} };
    } catch (err) {
        console.error("Error getting user state from Redis:", err);
        return { state: "initial", data: {} };
    }
}

async function setUserState(user_id, stateData) {
    try {
        await redisclient.set(`user_state:${user_id}`, JSON.stringify(stateData), "EX", 24 * 60 * 60);
    } catch (err) {
        console.error("Error setting user state in Redis:", err);
    }
}

let lastGeminiCallTime = 0;
const MINIMUM_GAP_MS = 4000;

async function getGeminiResponse(context, question, retryCount = 0) {
    const maxRetries = 3;
    const retryDelay = 60000;
    const maxContextTokens = 4000;
    const maxQuestionTokens = 500;

    try {
        console.log("Attempting Gemini API call...");
        const truncatedContext = context.length > maxContextTokens * 4 
            ? context.substring(0, maxContextTokens * 4) + " [Truncated]" 
            : context;
        const truncatedQuestion = question.length > maxQuestionTokens * 4 
            ? question.substring(0, maxQuestionTokens * 4) + " [Truncated]" 
            : question;

        const totalTokens = estimateTokens(truncatedContext) + estimateTokens(truncatedQuestion);
        console.log(`Token Estimate - Context: ${estimateTokens(truncatedContext)}, Question: ${estimateTokens(truncatedQuestion)}, Total: ${totalTokens}`);

        if (totalTokens > 5000) {
            console.error("Token limit exceeded in Gemini request");
            throw new Error("Input too large. Shorten your question or reduce context size.");
        }

        const currentTime = Date.now();
        const timeSinceLastCall = currentTime - lastGeminiCallTime;
        if (timeSinceLastCall < MINIMUM_GAP_MS) {
            console.log(`Waiting for ${MINIMUM_GAP_MS - timeSinceLastCall}ms before Gemini call`);
            await delay(MINIMUM_GAP_MS - timeSinceLastCall);
        }

        const prompt = `${truncatedContext}\n\n${truncatedQuestion}`;
        const result = await geminiModel.generateContent(prompt);
        const response = await result.response;
        const answer = response.text().trim();

        lastGeminiCallTime = Date.now();
        console.log("Gemini response received successfully");
        return answer;
    } catch (error) {
        console.error("Error in Gemini API call:", error.message);
        if (error.status === 429 && retryCount < maxRetries) {
            console.log(`Rate limit hit. Retrying in ${retryDelay / 1000}s... (${retryCount + 1}/${maxRetries})`);
            await delay(retryDelay);
            return await getGeminiResponse(context, question, retryCount + 1);
        }
        throw error;
    }
}

async function handleNormalConversation(user_id, question, userStateData) {
    try {
        console.log(`Handling normal conversation for user ${user_id}, question: ${question}`);
        const normalizedQuestion = question.trim().toLowerCase();
        const cachedResponse = await redisclient.get(`question:${normalizedQuestion}`);
        if (cachedResponse) {
            console.log("Returning cached response");
            return { answer: formatResponse(cachedResponse) };
        }

        let questions = JSON.parse(await readFile(questionsFile, "utf-8"));
        questions.push({ user_id, question, timestamp: new Date().toISOString() });
        await writeFile(questionsFile, JSON.stringify(questions, null, 2));

        const kbResponse = await fetchFromKB(question);
        let rawAnswer;
        if (kbResponse) {
            console.log("Using knowledge base response");
            rawAnswer = kbResponse;
        } else {
            const relevantKBContent = await fetchRelevantKBContent(question);
            const context = relevantKBContent 
                ? `You are a customer support assistant for ${COMPANY_NAME}. Relevant info: ${relevantKBContent}\n\n`
                : `You are a customer support assistant for ${COMPANY_NAME}.`;
            console.log(`Context Size: ${context.length}, Question Size: ${question.length}`);
            rawAnswer = await getGeminiResponse(context, question);
        }

        const finalAnswer = fixCommonTypos(rawAnswer);
        const formattedAnswer = formatResponse(finalAnswer);
        await redisclient.set(`question:${normalizedQuestion}`, formattedAnswer, "EX", 3600);
        await saveChatToDB(user_id, question, formattedAnswer);
        return { answer: formattedAnswer };
    } catch (err) {
        console.error("Error in handleNormalConversation:", err);
        throw err;
    }
}

const activeConnections = new Set();

setInterval(() => {
    wss.clients.forEach((ws) => {
        if (ws.isAlive === false) {
            ws.terminate();
            return;
        }
        ws.isAlive = false;
        ws.ping();
    });
}, 30000);

wss.on("connection", (ws) => {
    ws.isAlive = true;
    activeConnections.add(ws);

    ws.on("pong", () => {
        ws.isAlive = true;
    });

    ws.on("message", async (message) => {
        try {
            const data = JSON.parse(message.toString());
            const { user_id, product_id, latitude, longitude } = data;
            if (user_id && product_id && latitude && longitude) {
                const placeName = await getPlaceName(latitude, longitude);
                await storeLocationData(user_id, product_id, latitude, longitude, placeName);
                const locationData = { product_id, placeName, timestamp: new Date().toISOString() };
                activeConnections.forEach((client) => {
                    if (client.readyState === WebSocket.OPEN) {
                        client.send(JSON.stringify(locationData));
                    }
                });
            }
        } catch (err) {
            console.error("WebSocket message error:", err.message);
        }
    });

    ws.on("close", (code, reason) => {
        console.log(`WebSocket closed. Code: ${code}, Reason: ${reason.toString()}`);
        activeConnections.delete(ws);
    });

    ws.on("error", (err) => {
        console.error("WebSocket error:", err.message);
    });
});

// Scrape Endpoint for New URLs
app.post("/scrape", async (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ answer: "Please provide a URL to scrape." });
    }

    try {
        const scrapedContent = await scrapeWebsite(url);
        if (scrapedContent.startsWith("Error")) {
            return res.status(500).json({ answer: scrapedContent });
        }
        return res.json({ answer: `Successfully scraped and stored content from ${url}.` });
    } catch (err) {
        console.error("Error in /scrape endpoint:", err.message);
        return res.status(500).json({ answer: `Error scraping URL: ${err.message}` });
    }
});

// Dashboard Endpoints
// Get company settings
app.get("/api/settings", authenticateJWT, async (req, res) => {
    try {
        const companyId = req.user.username;
        const [settings] = await db.execute(
            "SELECT * FROM company_settings WHERE company_id = ?",
            [companyId]
        );
        if (settings.length === 0) {
            return res.status(404).json({ error: "Settings not found" });
        }
        res.json(settings[0]);
    } catch (err) {
        console.error("Error fetching settings:", err);
        res.status(500).json({ error: "Error fetching settings" });
    }
});

// Update company settings
app.post("/api/settings", authenticateJWT, async (req, res) => {
    const { logo_url, primary_color, welcome_message, features, language } = req.body;
    const companyId = req.user.username;

    try {
        await db.execute(
            `UPDATE company_settings 
             SET logo_url = ?, primary_color = ?, welcome_message = ?, features = ?, language = ?
             WHERE company_id = ?`,
            [logo_url || null, primary_color || null, welcome_message || null, JSON.stringify(features) || null, language || 'en', companyId]
        );
        res.json({ message: "Settings updated successfully" });
    } catch (err) {
        console.error("Error updating settings:", err);
        res.status(500).json({ error: "Error updating settings" });
    }
});

// Get knowledge base
app.get("/api/knowledge-base", authenticateJWT, async (req, res) => {
    try {
        const [rows] = await db.execute("SELECT * FROM knowledge_base");
        res.json(rows);
    } catch (err) {
        console.error("Error fetching knowledge base:", err);
        res.status(500).json({ error: "Error fetching knowledge base" });
    }
});

// Add to knowledge base
app.post("/api/knowledge-base", authenticateJWT, async (req, res) => {
    const { source, content } = req.body;
    if (!source || !content) {
        return res.status(400).json({ error: "Source and content are required" });
    }

    try {
        await db.execute(
            "INSERT INTO knowledge_base (source, content) VALUES (?, ?)",
            [source, content]
        );
        res.json({ message: "Knowledge base updated" });
    } catch (err) {
        console.error("Error adding to knowledge base:", err);
        res.status(500).json({ error: "Error adding to knowledge base" });
    }
});

// Delete from knowledge base
app.delete("/api/knowledge-base/:id", authenticateJWT, async (req, res) => {
    const { id } = req.params;
    try {
        const [result] = await db.execute(
            "DELETE FROM knowledge_base WHERE id = ?",
            [id]
        );
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Entry not found" });
        }
        res.json({ message: "Entry deleted" });
    } catch (err) {
        console.error("Error deleting from knowledge base:", err);
        res.status(500).json({ error: "Error deleting from knowledge base" });
    }
});

// Get analytics (basic)
app.get("/api/analytics", authenticateJWT, async (req, res) => {
    const companyId = req.user.username;

    try {
        const [subscription] = await db.execute(
            "SELECT plan FROM subscriptions WHERE company_id = ?",
            [companyId]
        );
        if (subscription.length === 0 || subscription[0].plan !== "premium") {
            return res.status(403).json({ error: "Upgrade to premium to access analytics" });
        }

        const [userCount] = await db.execute(
            "SELECT COUNT(DISTINCT user_id) as count FROM chat_logs WHERE user_id LIKE ?",
            [`${companyId}%`]
        );
        const [commonQuestions] = await db.execute(
            "SELECT message, COUNT(*) as count FROM chat_logs WHERE user_id LIKE ? GROUP BY message ORDER BY count DESC LIMIT 5",
            [`${companyId}%`]
        );
        res.json({
            totalUsers: userCount[0].count,
            commonQuestions
        });
    } catch (err) {
        console.error("Error fetching analytics:", err);
        res.status(500).json({ error: "Error fetching analytics" });
    }
});

// Subscription Endpoints
// Get subscription status
app.get("/api/subscription", authenticateJWT, async (req, res) => {
    try {
        const companyId = req.user.username;
        const [subscription] = await db.execute(
            "SELECT * FROM subscriptions WHERE company_id = ?",
            [companyId]
        );
        if (subscription.length === 0) {
            return res.status(404).json({ error: "Subscription not found" });
        }
        res.json(subscription[0]);
    } catch (err) {
        console.error("Error fetching subscription:", err);
        res.status(500).json({ error: "Error fetching subscription" });
    }
});

// Create Stripe checkout session
app.post("/api/create-checkout-session", authenticateJWT, async (req, res) => {
    const companyId = req.user.username;

    try {
        const [subscription] = await db.execute(
            "SELECT * FROM subscriptions WHERE company_id = ?",
            [companyId]
        );
        let customerId = subscription[0]?.stripe_customer_id;

        if (!customerId) {
            const customer = await stripe.customers.create({
                metadata: { companyId }
            });
            customerId = customer.id;
            await db.execute(
                "UPDATE subscriptions SET stripe_customer_id = ? WHERE company_id = ?",
                [customerId, companyId]
            );
        }

        const session = await stripe.checkout.sessions.create({
            customer: customerId,
            payment_method_types: ["card"],
            line_items: [
                {
                    price_data: {
                        currency: "usd",
                        product_data: {
                            name: "Premium Plan",
                        },
                        unit_amount: 5000, // $50.00
                        recurring: { interval: "month" },
                    },
                    quantity: 1,
                },
            ],
            mode: "subscription",
            success_url: `https://custommadebot-fresh.onrender.com/dashboard?success=true`,
            cancel_url: `https://custommadebot-fresh.onrender.com/dashboard?canceled=true`,
        });

        res.json({ url: session.url });
    } catch (err) {
        console.error("Error creating checkout session:", err);
        res.status(500).json({ error: "Error creating checkout session" });
    }
});

// Stripe webhook to handle subscription events
app.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
    const sig = req.headers["stripe-signature"];
    let event;

    try {
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            process.env.STRIPE_WEBHOOK_SECRET
        );
    } catch (err) {
        console.error("Webhook signature verification failed:", err);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === "customer.subscription.created" || event.type === "customer.subscription.updated") {
        const subscription = event.data.object;
        const companyId = subscription.customer_metadata?.companyId;

        if (companyId) {
            await db.execute(
                `UPDATE subscriptions 
                 SET plan = 'premium', stripe_subscription_id = ?, status = ? 
                 WHERE company_id = ?`,
                [subscription.id, subscription.status, companyId]
            );
        }
    }

    res.json({ received: true });
});

// Get company settings for chatbot
app.get("/api/company-settings/:companyId", async (req, res) => {
    const { companyId } = req.params;
    try {
        const [settings] = await db.execute(
            "SELECT * FROM company_settings WHERE company_id = ?",
            [companyId]
        );
        if (settings.length === 0) {
            return res.status(404).json({ error: "Settings not found" });
        }
        res.json(settings[0]);
    } catch (err) {
        console.error("Error fetching company settings:", err);
        res.status(500).json({ error: "Error fetching company settings" });
    }
});

// Updated /ask Endpoint with Feature Toggling and Subscription Restrictions
app.post("/ask", geminiRateLimiter, async (req, res) => {
    console.log("Received /ask request:", req.body);
    const { user_id, question } = req.body;

    if (!user_id || !question) {
        console.log("Invalid request: Missing user_id or question");
        return res.status(400).json({ answer: "Invalid request! Both user_id and question are required." });
    }

    try {
        console.log("Registering user...");
        await registerUser(user_id);
        console.log("Getting user state...");
        let userStateData = await getUserState(user_id);
        console.log(`User state: ${JSON.stringify(userStateData)}`);

        // Fetch company settings and subscription
        const [settings] = await db.execute(
            "SELECT * FROM company_settings WHERE company_id = ?",
            [user_id]
        );
        const [subscription] = await db.execute(
            "SELECT plan FROM subscriptions WHERE company_id = ?",
            [user_id]
        );
        const features = settings[0]?.features || {};
        const plan = subscription[0]?.plan || "freemium";

        console.log("Checking if contact info is missing...");
        const contactInfoMissing = await isContactInfoMissing(user_id);

        if (contactInfoMissing && userStateData.state === "initial") {
            console.log("User in initial state, asking for name");
            userStateData = { state: "asking_name", data: {} };
            await setUserState(user_id, userStateData);
            const greeting = getTimeBasedGreeting();
            return res.json({ answer: `${greeting}, ${user_id}! I am a representative of ${COMPANY_NAME}. What should I call you?` });
        }

        if (userStateData.state === "asking_name") {
            console.log("User provided name");
            userStateData.data.name = question;
            userStateData.state = "asking_consent";
            await setUserState(user_id, userStateData);
            return res.json({ answer: "Would you like to share your contact info?" });
        }

        if (userStateData.state === "asking_consent") {
            console.log("User responding to consent");
            const consent = question.toLowerCase();
            if (consent.includes("yes") || consent.includes("yeah") || consent.includes("sure")) {
                userStateData.state = "asking_email";
                await setUserState(user_id, userStateData);
                return res.json({ answer: "Please share your email id." });
            } else {
                await storeContactInfo(user_id, userStateData.data.name, null, null);
                userStateData.state = "normal";
                await setUserState(user_id, userStateData);
                return res.json({ answer: "Okay, let's continue. How can I assist you today?" });
            }
        }

        if (userStateData.state === "asking_email") {
            console.log("User provided email");
            userStateData.data.email = question;
            userStateData.state = "asking_number";
            await setUserState(user_id, userStateData);
            return res.json({ answer: "Please share your contact number." });
        }

        if (userStateData.state === "asking_number") {
            console.log("User provided number");
            userStateData.data.number = question;
            await storeContactInfo(user_id, userStateData.data.name, userStateData.data.email, userStateData.data.number);
            userStateData.state = "normal";
            await setUserState(user_id, userStateData);
            return res.json({ answer: "Thank you for sharing your contact info! How can I assist you today?" });
        }

        if (contactInfoMissing && wantsToShareContact(question)) {
            console.log("User wants to share contact");
            userStateData.state = "asking_email";
            await setUserState(user_id, userStateData);
            return res.json({ answer: "Great! Let's start with your email. Please share your email id." });
        }

        if (userStateData.state === "normal" && wantsToRaiseTicket(question)) {
            if (!features.ticketRaising) {
                return res.json({ answer: "Ticket raising is disabled by the company." });
            }
            if (plan !== "premium") {
                return res.json({ answer: "Please upgrade to the premium plan to raise tickets." });
            }
            console.log("User wants to raise a ticket");
            userStateData.state = "raising_ticket";
            userStateData.data.ticket_issue = question;
            userStateData.data.originalQuestion = question;
            await setUserState(user_id, userStateData);
            return res.json({ answer: "It looks like you have an issue. Please provide more details." });
        }

        if (userStateData.state === "raising_ticket") {
            console.log("User in raising ticket state");
            if (wantsToCancelProcess(question)) {
                const originalQuestion = userStateData.data.originalQuestion || "How can I assist you?";
                userStateData.state = "normal";
                userStateData.data = {};
                await setUserState(user_id, userStateData);
                const response = await handleNormalConversation(user_id, originalQuestion, userStateData);
                return res.json({ answer: `Okay, stopped ticket process. ${response.answer}` });
            }
            const ticketId = await raiseTicket(user_id, userStateData.data.ticket_issue);
            userStateData.state = "normal";
            userStateData.data = {};
            await setUserState(user_id, userStateData);

            const kbResponse = await fetchFromKB(userStateData.data.ticket_issue);
            let solution = kbResponse || await getGeminiResponse(
                `You are a customer support assistant for ${COMPANY_NAME}.`,
                `Customer issue: ${userStateData.data.ticket_issue}`
            );

            solution = fixCommonTypos(solution);
            return res.json({ answer: `Ticket #${ticketId} raised: "${userStateData.data.ticket_issue}". Solution: ${solution}. You can check ticket status by saying 'show tickets'. How can I assist you further?` });
        }

        if (userStateData.state === "normal" && wantsToSeeTicketHistory(question)) {
            if (plan !== "premium") {
                return res.json({ answer: "Please upgrade to the premium plan to view ticket history." });
            }
            console.log("User wants to see ticket history");
            const tickets = await fetchTicketHistory(user_id);
            if (tickets.length === 0) {
                return res.json({ answer: "No tickets raised yet. Want to raise one?" });
            }
            const history = tickets.map(ticket => 
                `ID: ${ticket.ticket_id}, Issue: ${ticket.issue}, Status: ${ticket.status}, Created: ${ticket.created_at}, Closed: ${ticket.closed_at || 'N/A'}`
            ).join("\n");
            return res.json({ answer: `Ticket history:\n${history}\nHow can I assist you further?` });
        }

        if (userStateData.state === "normal" && wantsToBookAppointment(question)) {
            if (!features.appointmentBooking) {
                return res.json({ answer: "Appointment booking is disabled by the company." });
            }
            if (plan !== "premium") {
                return res.json({ answer: "Please upgrade to the premium plan to book appointments." });
            }
            console.log("User wants to book appointment");
            userStateData.state = "asking_appointment_date";
            userStateData.data.originalQuestion = question;
            await setUserState(user_id, userStateData);
            return res.json({ answer: "Let's book your appointment! Please select a date (e.g., 2025-03-21)." });
        }

        if (userStateData.state === "asking_appointment_date") {
            console.log("User in asking appointment date state");
            if (wantsToCancelProcess(question)) {
                const originalQuestion = userStateData.data.originalQuestion || "How can I assist you?";
                userStateData.state = "normal";
                userStateData.data = {};
                await setUserState(user_id, userStateData);
                const response = await handleNormalConversation(user_id, originalQuestion, userStateData);
                return res.json({ answer: `Stopped appointment booking. ${response.answer}` });
            }
            const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
            if (!dateRegex.test(question)) {
                return res.json({ answer: "Please provide a valid date in YYYY-MM-DD format (e.g., 2025-03-21)." });
            }
            const selectedDate = new Date(question);
            const currentDate = new Date();
            if (selectedDate < currentDate) {
                return res.json({ answer: "Cannot book appointments in the past. Please select a future date." });
            }
            const availableSlots = await getAvailableSlots(question);
            if (availableSlots.length === 0) {
                return res.json({ answer: `No slots available on ${question}. Please select another date.` });
            }
            userStateData.data.appointment_date = question;
            userStateData.data.available_slots = availableSlots;
            userStateData.state = "showing_available_slots";
            await setUserState(user_id, userStateData);
            const slotList = availableSlots.map((slot, index) => `${index + 1}. ${slot}`).join("\n");
            return res.json({ answer: `Available slots on ${question}:\n${slotList}\nPlease select a slot by number (e.g., 1) or time (e.g., 10:00).` });
        }

        if (userStateData.state === "showing_available_slots") {
            console.log("User in showing available slots state");
            if (wantsToCancelProcess(question)) {
                const originalQuestion = userStateData.data.originalQuestion || "How can I assist you?";
                userStateData.state = "normal";
                userStateData.data = {};
                await setUserState(user_id, userStateData);
                const response = await handleNormalConversation(user_id, originalQuestion, userStateData);
                return res.json({ answer: `Stopped appointment booking. ${response.answer}` });
            }
            let selectedSlot;
            const slotIndex = parseInt(question) - 1;
            if (!isNaN(slotIndex) && slotIndex >= 0 && slotIndex < userStateData.data.available_slots.length) {
                selectedSlot = userStateData.data.available_slots[slotIndex];
            } else {
                const timeMatch = userStateData.data.available_slots.find(slot => slot.includes(question));
                if (timeMatch) {
                    selectedSlot = timeMatch;
                }
            }
            if (!selectedSlot) {
                const slotList = userStateData.data.available_slots.map((slot, index) => `${index + 1}. ${slot}`).join("\n");
                return res.json({ answer: `Invalid selection. Please select a slot by number or time:\n${slotList}` });
            }
            userStateData.data.appointment_time = selectedSlot;
            userStateData.state = "asking_appointment_purpose";
            await setUserState(user_id, userStateData);
            return res.json({ answer: "What’s the purpose of your appointment?" });
        }

        if (userStateData.state === "asking_appointment_purpose") {
            console.log("User in asking appointment purpose state");
            if (wantsToCancelProcess(question)) {
                const originalQuestion = userStateData.data.originalQuestion || "How can I assist you?";
                userStateData.state = "normal";
                userStateData.data = {};
                await setUserState(user_id, userStateData);
                const response = await handleNormalConversation(user_id, originalQuestion, userStateData);
                return res.json({ answer: `Stopped appointment booking. ${response.answer}` });
            }
            userStateData.data.appointment_purpose = question;
            const appointmentId = await storeAppointment(
                user_id,
                userStateData.data.appointment_time,
                userStateData.data.appointment_purpose
            );
            userStateData.state = "normal";
            await setUserState(user_id, userStateData);
            return res.json({ answer: `Appointment booked! ID: ${appointmentId}. How can I assist you further?` });
        }

        if (userStateData.state === "normal" && wantsToCancelAppointment(question)) {
            if (!features.appointmentBooking) {
                return res.json({ answer: "Appointment booking is disabled by the company." });
            }
            if (plan !== "premium") {
                return res.json({ answer: "Please upgrade to the premium plan to cancel appointments." });
            }
            console.log("User wants to cancel appointment");
            userStateData.state = "asking_appointment_id_to_cancel";
            await setUserState(user_id, userStateData);
            return res.json({ answer: "Provide the appointment ID to cancel. Say 'show my appointments' for history." });
        }

        if (userStateData.state === "asking_appointment_id_to_cancel") {
            console.log("User in asking appointment ID to cancel state");
            const appointmentId = question.trim();
            const success = await cancelAppointment(appointmentId, user_id);
            userStateData.state = "normal";
            await setUserState(user_id, userStateData);
            return res.json({ 
                answer: success 
                    ? `Appointment ID ${appointmentId} cancelled. How can I assist you further?` 
                    : `Couldn’t cancel ID ${appointmentId}. Check history with 'show my appointments'.` 
            });
        }

        if (userStateData.state === "normal" && wantsToSeeAppointmentHistory(question)) {
            if (plan !== "premium") {
                return res.json({ answer: "Please upgrade to the premium plan to view appointment history." });
            }
            console.log("User wants to see appointment history");
            const appointments = await fetchAppointmentHistory(user_id);
            if (appointments.length === 0) {
                return res.json({ answer: "No appointments booked yet. Want to book one?" });
            }
            const history = appointments.map(appt => 
                `ID: ${appt.appointment_id}, Time: ${appt.time}, Address: ${appt.address}, Purpose: ${appt.purpose}, Status: ${appt.status}`
            ).join("\n");
            return res.json({ answer: `Appointment history:\n${history}\nHow can I assist you further?` });
        }

        console.log("Processing normal conversation...");
        const response = await handleNormalConversation(user_id, question, userStateData);
        res.json(response);
    } catch (error) {
        console.error("Error in /ask endpoint:", error.message);
        res.status(500).json({ answer: "Error occurred! Please try again later.", error: error.message });
    }
});

let scrapedContent = "";
server.listen(PORT, async () => {
    console.log(`Server running on https://custommadebot-fresh.onrender.com`);
    const scrapeResult = await scrapeWebsite(SCRAPE_URL);
    if (typeof scrapeResult === "string" && !scrapeResult.startsWith("Error")) {
        scrapedContent = scrapeResult;
    }

    try {
        await db.execute(`
            CREATE TABLE IF NOT EXISTS location_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(255),
                product_id VARCHAR(255),
                latitude DECIMAL(9,6),
                longitude DECIMAL(9,6),
                place_name TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        console.log("location_logs table created or already exists");

        await db.execute(`
            CREATE TABLE IF NOT EXISTS company_settings (
                company_id VARCHAR(255) PRIMARY KEY,
                logo_url VARCHAR(255),
                primary_color VARCHAR(7),
                welcome_message TEXT,
                features JSON,
                language VARCHAR(10) DEFAULT 'en'
            )
        `);
        console.log("company_settings table created or already exists");

        await db.execute(`
            CREATE TABLE IF NOT EXISTS subscriptions (
                company_id VARCHAR(255) PRIMARY KEY,
                plan VARCHAR(20) DEFAULT 'freemium',
                stripe_customer_id VARCHAR(255),
                stripe_subscription_id VARCHAR(255),
                status VARCHAR(20) DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (company_id) REFERENCES users(username)
            )
        `);
        console.log("subscriptions table created or already exists");

        await db.execute(`
            CREATE TABLE IF NOT EXISTS user_contacts (
                user_id VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255),
                email VARCHAR(255),
                number VARCHAR(20),
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        `);
        console.log("user_contacts table created or already exists");
    } catch (err) {
        console.error("Error creating tables:", err);
    }
});