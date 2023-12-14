import type { Request, Response } from "express";
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function hash(password: string) {
  return bcrypt.hashSync(password, bcrypt.genSaltSync(12));
}

function compare(hash: string, password: string) {
  return bcrypt.compareSync(password, hash);
}

type User = {
  name: string;
  email: string;
  password: string;
};

const secret = "secret";
const users: User[] = [];

app.post("/sign-in", async (req: Request, res: Response) => {
  const { email, password } = req.body as Omit<User, "name">;

  let user: User = { name: "", email: "", password: "" };
  for (const u of users) {
    if (u.email === email && compare(u.password, password)) {
      user = u;
      break;
    }
  }

  const expTime = Math.floor(Date.now() / 1000 + 60 * 30);
  const token = jwt.sign({ email }, secret, {
    expiresIn: expTime,
  });

  res.status(200).setHeader("X-JWT-Token", token).json({
    success: true,
    user,
  });
});

app.post("/sign-up", async (req: Request, res: Response) => {
  const { name, email, password } = req.body as User;
  users.push({
    name,
    email,
    password: hash(password),
  });
  res.status(201).json({
    success: true,
  });
});

app.post("/me", async (req: Request, res: Response) => {
  const { authorization } = req.headers;
  if (authorization === undefined) {
    throw new Error("No authorization key set");
  }

  const token = jwt.verify(authorization, secret);
  let email: string = "";

  if (typeof token === "object") {
    email = token.email || ""
  } else {
    throw new Error("Invalid token");
  }
  

  let user: User = { name: "", email: "", password: "" };
  for (const u of users) {
    if (u.email === email) {
      user = u;
      break;
    }
  }

  res.status(200).json({
    success: true,
    user,
  });
});

app.listen(3000, () => {
  console.info("Starting");
});
