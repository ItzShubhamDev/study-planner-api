# Study Planar API

An API to manage your study sessions, topics and subjects to strategically plan your study times.

## Prerequisites

`Node.js` >= 20

## Installation

```bash
git clone https://github.com/ItzShubhamDev/study-planner-api
cd study-planner-api
npm install
```

## Run Development Server

```bash
npm run dev
```

## Deployment

```bash
npm run build
npm run start
```

## Environmet Variables

`SECRET` - Required for encrypting data on the database. <br />
`PORT` - The port to run the server on. <br />
`DB` - The location to store database.

## API Endpoints

### No Auth Needed

| Method | Endpoint         | Summary                |
| ------ | ---------------- | ---------------------- |
| POST   | `/auth/register` | Registers a new user   |
| POST   | `/auth/login`    | Login an existing user |

### Bearer Token Auth

| Method | Endpoint                       | Summary                                    |
| ------ | ------------------------------ | ------------------------------------------ |
| GET    | `/auth/user`                   | Get current user info                      |
| GET    | `/subjects`                    | Get all subjects of the user               |
| POST   | `/subjects`                    | Create a new subject                       |
| GET    | `/subjects/{id}`               | Get subject details with topics & sessions |
| PUT    | `/subjects/{id}`               | Update a subject                           |
| DELETE | `/subjects/{id}`               | Delete a subject                           |
| GET    | `/subjects/{subjectId}/topics` | Get topics of a subject                    |
| POST   | `/subjects/{subjectId}/topics` | Create a new topic                         |
| GET    | `/topics/{topicId}`            | Get topic details with sessions            |
| PUT    | `/topics/{topicId}`            | Update a topic (name, status)              |
| DELETE | `/topics/{topicId}`            | Delete a topic                             |
| GET    | `/topics/{topicId}/sessions`   | Get sessions for a topic                   |
| POST   | `/topics/{topicId}/sessions`   | Add a new session to a topic               |
