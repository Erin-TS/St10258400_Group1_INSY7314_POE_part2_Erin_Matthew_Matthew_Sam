// This file is used to connect to the MongoDB database using the connection string stored in the .env file.

import { MongoClient } from "mongodb";
import dotenv from "dotenv";
dotenv.config();

const connectionString = process.env.ATLAS_URI || "";

console.log(connectionString);

const client = new MongoClient(connectionString);

let conn;
try {
    conn = await client.connect();
    console.log("Connected to MongoDB!!");
} catch (error) {
    console.error("Error connecting to MongoDB:", error);
}

// Access database from connected client
const db = client.db("INSY7314-Cluster");

export default db;
