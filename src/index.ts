import express, { Request, Response } from "express";
import jwt from "jsonwebtoken";
import Sqlite from "better-sqlite3";
import bcrypt from "bcrypt";

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

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
