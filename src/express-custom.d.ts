import { User } from "./types";

declare namespace Express {
    export interface Request {
        user?: User;
    }
}
