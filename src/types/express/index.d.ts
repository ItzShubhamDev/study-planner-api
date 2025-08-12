import { User } from "..";

declare namespace Express {
    export interface Request {
        user?: User;
    }
}
