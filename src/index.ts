import express, { Request, Response } from "express";
import jwt from "jsonwebtoken";
import Sqlite from "better-sqlite3";
import bcrypt from "bcrypt";

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

app.post("/auth/register", async (req: Request, res: Response) => {
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
    const user = res.locals.user as User;
    return res.json(user);
});

app.get("/subjects", authHandler, (req: Request, res: Response) => {
    const rows = db
        .prepare(
            "SELECT id, user_id, name, created_at FROM subjects WHERE user_id = ?"
        )
        .all(res.locals.user.id);
    return res.json(rows);
});

app.get("/subjects/:id", authHandler, (req: Request, res: Response) => {
    const subjectId = parseInt(req.params.id);
    const subject = db
        .prepare(
            "SELECT id, user_id, name, created_at FROM subjects WHERE id = ? AND user_id = ?"
        )
        .get(subjectId, res.locals.user.id);
    if (!subject) {
        return res.status(404).json({ error: "Subject not found." });
    }
    return res.json(subject);
});

app.post("/subjects", authHandler, (req: Request, res: Response) => {
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

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
