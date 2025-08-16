/**
 * @swagger
 * tags:
 *   - name: Auth
 *     description: Authentication endpoints
 *   - name: Subjects
 *     description: Subjects endpoints
 *   - name: Topics
 *     description: Topics endpoints
 *   - name: Sessions
 *     description: Sessions endpoints
 */

import express, { Request, Response } from "express";
import jwt from "jsonwebtoken";
import Sqlite from "better-sqlite3";
import bcrypt from "bcrypt";
import swaggerJsDoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";

interface User {
    id: number;
    name: string;
    email: string;
}

interface Subject {
    id: number;
    user_id: number;
    name: string;
    created_at: string;
}

interface Topic {
    id: number;
    subject_id: number;
    name: string;
    status: "pending" | "in_progress" | "completed";
    created_at: string;
}

interface Session {
    id: number;
    topic_id: number;
    start_time: string;
    duration: number;
    notes?: string;
    created_at: string;
}

import { config } from "dotenv";
config();

const SECRET = process.env.SECRET;
const PORT = process.env.PORT || 3000;
const DB = process.env.DB || "database.sqlite";

const db = new Sqlite(DB);

db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS subjects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS topics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        subject_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        status TEXT CHECK(status IN ('pending', 'in_progress', 'completed')) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        topic_id INTEGER NOT NULL,
        start_time TEXT NOT NULL,
        duration INTEGER NOT NULL,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (topic_id) REFERENCES topics(id) ON DELETE CASCADE
    );
`);

if (!SECRET) {
    console.error("SECRET environment variable is not set.");
    process.exit(1);
}

const generateToken = (user: User) => {
    return jwt.sign(
        {
            id: user.id,
            email: user.email,
        },
        SECRET,
        {
            expiresIn: "14d",
        }
    );
};

const authHandler = (req: Request, res: Response, next: () => void) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res
            .status(401)
            .json({ error: "Authorization header is missing." });
    }
    const authHeaderParts = authHeader.split(" ");
    if (authHeaderParts.length !== 2 || authHeaderParts[0] !== "Bearer") {
        return res.status(401).json({ error: "Invalid authorization format." });
    }
    const token = authHeaderParts[1];

    try {
        const payload = jwt.verify(token, SECRET) as User;
        res.locals.user = payload;
        next();
    } catch (error) {
        return res.status(401).json({ error: "Invalid or expired token." });
    }
};

const app = express();
app.use(express.json());

app.get("/", (_req: Request, res: Response) => {
    res.json({
        name: "Study Planner API",
        version: "1.0.0",
        description:
            "An API provides endpoints for planning your study topics and subjects.",
        status: "OK",
        endpoints: [],
    });
});

// Authentication Endpoints
app.post("/auth/register", async (req: Request, res: Response) => {
    /**
     * @swagger
     * /auth/register:
     *   post:
     *     summary: Registers a new user
     *     tags: [Auth]
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [name, email, password]
     *             properties:
     *               name:
     *                 type: string
     *               email:
     *                 type: string
     *                 format: email
     *               password:
     *                 type: string
     *     responses:
     *       200:
     *         description: Successfully registered
     *       400:
     *         description: Missing fields or already exists
     */
    const { name, email, password } = req.body;
    if (!name || !email || !password)
        return res.status(400).json({ error: "Missing required fields." });
    try {
        const hash = await bcrypt.hash(password, 10);
        const stmt = db.prepare(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)"
        );
        const r = stmt.run(name, email, hash);
        const user: User = {
            id: r.lastInsertRowid as number,
            name,
            email,
        };
        const token = generateToken(user);
        return res.json({ user, token });
    } catch (e: any) {
        if (e.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(400).json({ error: "Email already exists." });
        }
        console.error("Error hashing password:", e);
        return res.status(500).json({ error: "Internal server error." });
    }
});

app.post("/auth/login", async (req: Request, res: Response) => {
    /**
     * @swagger
     * /auth/login:
     *   post:
     *     summary: Login an existing user
     *     tags: [Auth]
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [email, password]
     *             properties:
     *               email:
     *                 type: string
     *                 format: email
     *               password:
     *                 type: string
     *     responses:
     *       200:
     *         description: Returns user along with a JWT token
     *       401:
     *         description: Invalid credentials
     */
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: "Missing required fields." });
    try {
        const row = db
            .prepare(
                "SELECT id, name, email, password FROM users WHERE email = ?"
            )
            .get(email) as
            | {
                  id: number;
                  name: string;
                  email: string;
                  password?: string;
              }
            | undefined;
        if (!row) {
            return res.status(401).json({ error: "Invalid credentials." });
        }
        const check = await bcrypt.compare(password, row.password!);
        if (!check) {
            return res.status(401).json({ error: "Invalid credentials." });
        }
        const user: User = {
            id: row.id,
            name: row.name,
            email: row.email,
        };
        const token = generateToken(user);
        return res.json({
            user,
            token,
        });
    } catch (e: any) {
        console.error("Error during login:", e);
        return res.status(500).json({ error: "Internal server error." });
    }
});

app.get("/auth/user", authHandler, (req: Request, res: Response) => {
    /**
     * @swagger
     * /auth/user:
     *   get:
     *     summary: Get current user
     *     tags: [Auth]
     *     security:
     *       - bearerAuth: []
     *     responses:
     *       200:
     *         description: Returns the current user
     *         content:
     *           application/json:
     *              schema:
     *                  $ref: '#/components/schemas/User'
     *       401:
     *         description: Unauthorized
     */
    const user = res.locals.user as User;
    return res.json(user);
});

// Subjects Endpoints
app.get("/subjects", authHandler, (req: Request, res: Response) => {
    /**
     * @swagger
     * /subjects:
     *   get:
     *     summary: Get all subjects of the user
     *     tags: [Subjects]
     *     security:
     *       - bearerAuth: []
     *     responses:
     *       200:
     *         description: List of subjects
     *         content:
     *             application/json:
     *               schema:
     *                 type: array
     *                 items:
     *                   $ref: '#/components/schemas/Subject'
     */
    const rows = db
        .prepare(
            "SELECT id, user_id, name, created_at FROM subjects WHERE user_id = ?"
        )
        .all(res.locals.user.id);
    return res.json(rows);
});

app.get("/subjects/:id", authHandler, (req: Request, res: Response) => {
    /**
     * @swagger
     * /subjects/{id}:
     *   get:
     *     summary: Get subject details with ith topics & sessions)
     *     tags: [Subjects]
     *     security:
     *       - bearerAuth: []
     *     parameters:
     *       - in: path
     *         name: id
     *         required: true
     *         schema:
     *           type: integer
     *     responses:
     *       200:
     *         description: Subject with topics and sessions
     *         content:
     *           application/json:
     *             schema:
     *               $ref: '#/components/schemas/Subject'
     *       404:
     *         description: Subject not found
     */
    const subjectId = parseInt(req.params.id);
    const subject = db
        .prepare(
            "SELECT id, user_id, name, created_at FROM subjects WHERE id = ? AND user_id = ?"
        )
        .get(subjectId, res.locals.user.id);
    if (!subject) {
        return res.status(404).json({ error: "Subject not found." });
    }

    const result = [];
    const topics = db
        .prepare(
            "SELECT id, name, status, created_at FROM topics WHERE subject_id = ?"
        )
        .all(subjectId) as Topic[];

    for (const t of topics) {
        const sessions = db
            .prepare(
                "SELECT id, start_time, duration, notes, created_at FROM sessions WHERE topic_id = ?"
            )
            .all(t.id) as Session[];
        const topic = {
            ...t,
            sessions,
        };

        result.push(topic);
    }

    return res.json({
        ...subject,
        topics: result,
    });
});

app.post("/subjects", authHandler, (req: Request, res: Response) => {
    /**
     * @swagger
     * /subjects:
     *   post:
     *     summary: Create a subject
     *     tags: [Subjects]
     *     security:
     *       - bearerAuth: []
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [name]
     *             properties:
     *               name:
     *                 type: string
     *     responses:
     *       201:
     *         description: Created subject
     *         content:
     *           application/json:
     *             schema:
     *                 $ref: '#/components/schemas/Subject'
     */
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: "Name is required." });
    const stmt = db.prepare(
        "INSERT INTO subjects (user_id, name) VALUES (?, ?)"
    );
    const r = stmt.run(res.locals.user.id, name);

    const subject = db
        .prepare("SELECT * FROM subjects WHERE id = ?")
        .get(r.lastInsertRowid as number) as Subject;

    return res.status(201).json(subject);
});

app.put("/subjects/:id", authHandler, (req: Request, res: Response) => {
    /**
     * @swagger
     * /subjects/{id}:
     *   put:
     *     summary: Updates a subject
     *     tags: [Subjects]
     *     security:
     *       - bearerAuth: []
     *     parameters:
     *       - in: path
     *         name: id
     *         required: true
     *         schema:
     *           type: integer
     *     requestBody:
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             required: [name]
     *             properties:
     *               name:
     *                 type: string
     *     responses:
     *       200:
     *         description: Updated subject
     *         content:
     *           application/json:
     *             schema:
     *                 $ref: '#/components/schemas/Subject'
     */
    const subjectId = parseInt(req.params.id);
    const { name } = req.body;

    if (!name) return res.status(400).json({ error: "Name is required." });

    const subject = db
        .prepare("SELECT id FROM subjects WHERE id = ? AND user_id = ?")
        .get(subjectId, res.locals.user.id);

    if (!subject) {
        return res.status(404).json({ error: "Subject not found." });
    }

    const stmt = db.prepare(
        "UPDATE subjects SET name = ? WHERE id = ? AND user_id = ?"
    );

    stmt.run(name, subjectId, res.locals.user.id);

    const updatedSubject = db
        .prepare("SELECT * FROM subjects WHERE id = ? AND user_id = ?")
        .get(subjectId, res.locals.user.id) as Subject;

    return res.json(updatedSubject);
});

app.delete("/subjects/:id", authHandler, (req: Request, res: Response) => {
    /**
     * @swagger
     * /subjects/{id}:
     *   delete:
     *     summary: Deletes a subject
     *     tags: [Subjects]
     *     security:
     *       - bearerAuth: []
     *     parameters:
     *       - in: path
     *         name: id
     *         required: true
     *         schema:
     *           type: integer
     *     responses:
     *       204:
     *         description: Deleted successfully
     */
    const subjectId = parseInt(req.params.id);

    const subject = db
        .prepare("SELECT id FROM subjects WHERE id = ? and user_id = ?")
        .get(subjectId, res.locals.user.id);

    if (!subject) {
        return res.status(404).json({ error: "Subject not found." });
    }

    db.prepare("DELETE FROM subjects WHERE id = ?").run(subjectId);

    return res.status(204).send();
});

// Topics Endpoints

app.get(
    "/subjects/:subjectId/topics",
    authHandler,
    (req: Request, res: Response) => {
        /**
         * @swagger
         * /subjects/{subjectId}/topics:
         *   get:
         *     summary: Get topics of a subject
         *     tags: [Topics]
         *     security:
         *       - bearerAuth: []
         *     parameters:
         *       - in: path
         *         name: subjectId
         *         required: true
         *         schema:
         *           type: integer
         *     responses:
         *       200:
         *         description: List of topics
         *         content:
         *           application/json:
         *             schema:
         *               type: array
         *               items:
         *                 $ref: '#/components/schemas/Topic'
         */
        const subjectId = parseInt(req.params.subjectId);
        const subject = db
            .prepare("SELECT id FROM subjects WHERE id = ? AND user_id = ?")
            .get(subjectId, res.locals.user.id);
        if (!subject) {
            return res.status(404).json({ error: "Subject not found." });
        }

        const topics = db
            .prepare(
                "SELECT id, subject_id, name, status, created_at FROM topics WHERE subject_id = ?"
            )
            .all(subjectId);

        return res.json(topics);
    }
);

app.get("/topics/:topicId", authHandler, (req: Request, res: Response) => {
    /**
     * @swagger
     * /topics/{topicId}:
     *   get:
     *     summary: Get topic details (with sessions)
     *     tags: [Topics]
     *     security:
     *       - bearerAuth: []
     *     parameters:
     *       - in: path
     *         name: topicId
     *         required: true
     *         schema:
     *           type: integer
     *     responses:
     *       200:
     *         description: Topic with sessions
     *         content:
     *           application/json:
     *             schema:
     *                 $ref: '#/components/schemas/Topic'
     */
    const topicId = parseInt(req.params.topicId);
    const topic = db
        .prepare(
            "SELECT id, subject_id, name, status, created_at FROM topics WHERE id = ?"
        )
        .get(topicId) as Topic | undefined;
    if (!topic) {
        return res.status(404).json({ error: "Topic not found." });
    }
    const subject = db
        .prepare("SELECT user_id FROM subjects WHERE id = ?")
        .get(topic.subject_id) as Subject | undefined;

    if (!subject || subject.user_id !== res.locals.user.id) {
        return res.status(404).json({
            error: "Topic not found.",
        });
    }

    const sessions = db
        .prepare(
            "SELECT id, start_time, duration, notes, created_at FROM sessions WHERE topic_id = ?"
        )
        .all(topicId) as Session[] | undefined;

    return res.json({ ...topic, sessions });
});

app.post(
    "/subjects/:subjectId/topics",
    authHandler,
    (req: Request, res: Response) => {
        /**
         * @swagger
         * /subjects/{subjectId}/topics:
         *   post:
         *     summary: Create a new topic for a subject
         *     tags: [Topics]
         *     security:
         *       - bearerAuth: []
         *     parameters:
         *       - in: path
         *         name: subjectId
         *         required: true
         *         schema:
         *           type: integer
         *     requestBody:
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             required: [name]
         *             properties:
         *               name:
         *                 type: string
         *     responses:
         *       201:
         *         description: Created topic
         *         content:
         *           application/json:
         *             schema:
         *                 $ref: '#/components/schemas/Topic'
         */
        const subjectId = parseInt(req.params.subjectId);
        const { name } = req.body;
        const subject = db
            .prepare("SELECT user_id FROM subjects WHERE id = ?")
            .get(subjectId) as Subject;

        if (!subject || subject.user_id !== res.locals.user.id) {
            return res.status(404).json({
                error: "Topic not found.",
            });
        }

        const stmt = db.prepare(
            "INSERT INTO topics (subject_id, name) VALUES (?, ?)"
        );
        const r = stmt.run(subjectId, name);

        const topic = db
            .prepare(
                "SELECT id, subject_id, name, status, created_at FROM topics WHERE id = ?"
            )
            .get(r.lastInsertRowid as number) as Topic;

        return res.status(201).json(topic);
    }
);

app.put("/topics/:topicId", authHandler, (req: Request, res: Response) => {
    /**
     * @swagger
     * /topics/{topicId}:
     *   put:
     *     summary: Updates a topic
     *     tags: [Topics]
     *     security:
     *       - bearerAuth: []
     *     parameters:
     *       - in: path
     *         name: topicId
     *         required: true
     *         schema:
     *           type: integer
     *     requestBody:
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             properties:
     *               name:
     *                 type: string
     *               status:
     *                 type: string
     *                 enum: [pending, in_progress, completed]
     *     responses:
     *       200:
     *         description: Updated topic
     *         content:
     *           application/json:
     *             schema:
     *                 $ref: '#/components/schemas/Topic'
     */
    const topicId = parseInt(req.params.topicId);

    const { name, status } = req.body;
    if (!name && !status) {
        return res.status(404).json({
            error: "Name or status is required.",
        });
    }

    const topic = db
        .prepare("SELECT id, subject_id, name, status FROM topics WHERE id = ?")
        .get(topicId) as Topic | undefined;

    if (!topic) {
        return res.status(404).json({ error: "Topic not found." });
    }

    const subject = db
        .prepare("SELECT user_id FROM subjects WHERE id = ?")
        .get(topic.subject_id) as Subject;

    if (!subject || subject.user_id !== res.locals.user.id) {
        return res.status(404).json({
            error: "Topic not found.",
        });
    }

    const stmt = db.prepare(
        `UPDATE topics SET ${name ? "name = ?" : ""} ${
            name && status ? ", status = ?" : status ? "status = ?" : ""
        } WHERE id = ?`
    );

    const params: (string | number)[] = [];
    if (name) params.push(name);
    if (status) params.push(status);
    params.push(topicId);

    stmt.run(...params);

    const updated = db
        .prepare(
            "SELECT id, subject_id, name, status, created_at FROM topics WHERE id = ?"
        )
        .get(topicId) as Topic;

    return res.json(updated);
});

app.delete("/topics/:topicId", authHandler, (req: Request, res: Response) => {
    /**
     * @swagger
     * /topics/{topicId}:
     *   delete:
     *     summary: Deletes a topic
     *     tags: [Topics]
     *     security:
     *       - bearerAuth: []
     *     parameters:
     *       - in: path
     *         name: topicId
     *         required: true
     *         schema:
     *           type: integer
     *     responses:
     *       204:
     *         description: Deleted successfully
     */
    const topicId = parseInt(req.params.topicId);
    const topic = db
        .prepare("SELECT id, subject_id FROM topics WHERE id = ?")
        .get(topicId) as Topic | undefined;

    if (!topic) {
        return res.status(404).json({
            error: "Topic not found.",
        });
    }

    const subject = db
        .prepare("SELECT user_id FROM subjects WHERE id = ?")
        .get(topic.subject_id) as Subject | undefined;

    if (!subject || subject.user_id !== res.locals.user.id) {
        return res.status(404).json({
            error: "Topic not found.",
        });
    }

    db.prepare("DELETE FROM topics WHERE id = ?").run(topicId);

    return res.status(204).send();
});

// Sessions

app.get(
    "/topics/:topicId/sessions",
    authHandler,
    (req: Request, res: Response) => {
        /**
         * @swagger
         * /topics/{topicId}/sessions:
         *   get:
         *     summary: Get sessions for a topic
         *     tags: [Sessions]
         *     security:
         *       - bearerAuth: []
         *     parameters:
         *       - in: path
         *         name: topicId
         *         required: true
         *         schema:
         *           type: integer
         *     responses:
         *       200:
         *         description: List of sessions
         *         content:
         *           application/json:
         *             schema:
         *               type: array
         *               items:
         *                 $ref: '#/components/schemas/Session'
         */
        const topicId = parseInt(req.params.topicId);
        const topic = db
            .prepare("SELECT id, subject_id FROM topics WHERE id = ?")
            .get(topicId) as Topic | undefined;

        if (!topic) {
            return res.status(404).json({
                error: "Topic not found.",
            });
        }

        const subject = db
            .prepare("SELECT user_id FROM subjects WHERE id = ?")
            .get(topic.subject_id) as Subject | undefined;

        if (!subject || subject.user_id !== res.locals.user.id) {
            return res.status(404).json({
                error: "Topic not found.",
            });
        }

        const sessions = db
            .prepare(
                "SELECT id, start_time, duration, notes, created_at FROM sessions WHERE topic_id = ?"
            )
            .all(topicId) as Session[];

        return res.json(sessions);
    }
);

app.post(
    "/topics/:topicId/sessions",
    authHandler,
    (req: Request, res: Response) => {
        /**
         * @swagger
         * /topics/{topicId}/sessions:
         *   post:
         *     summary: Add a new session for a topic
         *     tags: [Sessions]
         *     security:
         *       - bearerAuth: []
         *     parameters:
         *       - in: path
         *         name: topicId
         *         required: true
         *         schema:
         *           type: integer
         *     requestBody:
         *       content:
         *         application/json:
         *           schema:
         *             type: object
         *             required: [start_time, duration]
         *             properties:
         *               start_time:
         *                 type: string
         *                 example: "2025-08-17T12:00:00Z"
         *               duration:
         *                 type: integer
         *                 example: 60
         *               notes:
         *                 type: string
         *     responses:
         *       201:
         *         description: Created session
         *         content:
         *           application/json:
         *             schema:
         *                 $ref: '#/components/schemas/Topic'
         */
        const topicId = parseInt(req.params.topicId);
        const topic = db
            .prepare("SELECT id, subject_id, status FROM topics WHERE id = ?")
            .get(topicId) as Topic | undefined;

        if (!topic) {
            return res.status(404).json({
                error: "Topic not found.",
            });
        }

        const subject = db
            .prepare("SELECT user_id FROM subjects WHERE id = ?")
            .get(topic.subject_id) as Subject | undefined;

        if (!subject || subject.user_id !== res.locals.user.id) {
            return res.status(404).json({
                error: "Topic not found",
            });
        }

        if (topic.status === "completed") {
            return res.status(400).json({
                error: "Topic already completed, unable to add sessions.",
            });
        }

        const { start_time, duration, notes } = req.body;

        if (!start_time || !duration) {
            return res.status(400).json({
                error: "Start time and duration are required.",
            });
        }

        try {
            new Date(start_time);
        } catch {
            return res.status(400).json({
                error: 'Invalid start time format. Format should be "YYYY-MM-DDThh:mm:ssZ" in UTC.',
            });
        }

        const stmt = db.prepare(
            "INSERT INTO sessions (topic_id, start_time, duration, notes) VALUES (?, ?, ?, ?)"
        );

        const r = stmt.run(topicId, start_time, duration, notes || null);

        const session = db
            .prepare(
                "SELECT id, topic_id, start_time, duration, notes, created_at FROM sessions WHERE id = ?"
            )
            .get(r.lastInsertRowid) as Session | undefined;

        return res.status(201).json(session);
    }
);

const options = {
    definition: {
        openapi: "3.1.0",
        info: {
            title: "Study Planner API",
            version: "1.0.0",
            description:
                "An API to manage your study sessions, topics and subjects to strategically plan your study times.",
        },
        servers: [
            {
                url: `http://localhost:${PORT}`,
            },
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: "http",
                    scheme: "bearer",
                    bearerFormat: "JWT",
                },
            },
            schemas: {
                User: {
                    type: "object",
                    properties: {
                        id: {
                            type: "integer",
                        },
                        name: {
                            type: "string",
                        },
                        email: {
                            type: "string",
                            format: "email",
                        },
                    },
                },
                Subject: {
                    type: "object",
                    properties: {
                        id: {
                            type: "integer",
                        },
                        user_id: {
                            type: "integer",
                        },
                        name: {
                            type: "string",
                        },
                        created_at: {
                            type: "string",
                            format: "date-time",
                        },
                    },
                },
                Topic: {
                    type: "object",
                    properties: {
                        id: {
                            type: "integer",
                        },
                        subject_id: {
                            type: "integer",
                        },
                        name: {
                            type: "string",
                        },
                        status: {
                            type: "string",
                            enum: ["pending", "in_progress", "completed"],
                        },
                        created_at: {
                            type: "string",
                            format: "date-time",
                        },
                    },
                },
                Session: {
                    type: "object",
                    properties: {
                        id: {
                            type: "integer",
                        },
                        topic_id: {
                            type: "integer",
                        },
                        start_time: {
                            type: "string",
                            format: "date-time",
                        },
                        duration: {
                            type: "integer",
                        },
                        notes: {
                            type: "string",
                            nullable: true,
                        },
                        created_at: {
                            type: "string",
                            format: "date-time",
                        },
                    },
                },
            },
        },
    },
    apis: ["./src/index.ts"],
};

const specs = swaggerJsDoc(options);
app.use("/docs", swaggerUi.serve, swaggerUi.setup(specs));

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
