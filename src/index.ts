import express, { Request, Response } from "express";
import jwt from "jsonwebtoken";
import Sqlite from "better-sqlite3";
import bcrypt from "bcrypt";

interface User {
    id: number;
    name: string;
    email: string;
}

import { config } from "dotenv";
config();

const SECRET = process.env.SECRET;
const PORT = process.env.PORT || 3000;
const DB = process.env.DB || "database.sqlite";

const db = new Sqlite(DB);

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

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
