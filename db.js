import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

export const initDB = async () => {
    const db = await open({
        filename: './auth.db',
        driver: sqlite3.Database,
    });

    // 1. Create Users Table (from original lab)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT CHECK (role IN ('admin', 'user')) DEFAULT 'user'
        );
    `);

    // 2. Create Access Tokens Table (from original lab)
    await db.exec(`
        CREATE TABLE IF NOT EXISTS access_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT UNIQUE,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    `);
    
    // 3. Create Tasks Table (Mini-Project Requirement)
    // This table implements data ownership via the owner_id
    await db.exec(`
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            owner_id INTEGER,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );
    `);

    return db;
};