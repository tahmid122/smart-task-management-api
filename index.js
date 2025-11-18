require("dotenv").config();
const express = require("express");
const app = express();
const PORT = process.env.PORT || 3000;
const cors = require("cors");
const bcrypt = require("bcrypt");
const saltRounds = 10;
let jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion } = require("mongodb");
const mongoUri = process.env.MONGO_URI;
// middlewares
app.use(cors({ origin: ["http://localhost:5173"], credentials: true }));
app.use(express.json());
// mongodb
const client = new MongoClient(`${mongoUri}`, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    // collections
    const db = client.db("smart_task_management");
    const usersCollection = db.collection("users");
    const teamsCollection = db.collection("teams");
    const projectsCollection = db.collection("projects");
    const activitiesCollection = db.collection("activities");

    // Signup user
    app.post("/sign-up", async (req, res) => {
      const newUser = req.body;
      bcrypt.hash(newUser.password, saltRounds, async function (err, hash) {
        if (err) {
          return res.send({
            success: false,
            message: "Something went wrong to hash password",
            data: [],
          });
        }
        try {
          const createNewUser = await usersCollection.insertOne({
            ...newUser,
            password: hash,
          });
          if (createNewUser.insertedId) {
            res.send({
              success: true,
              message: "Signup successful",
              data: [createNewUser],
            });
          } else {
            res.send({
              success: false,
              message: "Signup failed. Please try again letter",
              data: [],
            });
          }
        } catch (error) {
          res.send({
            success: false,
            message: "Something went wrong",
            error: error.message,
          });
        }
      });
    });
    // login user
    app.post("/login", async (req, res) => {
      const { email, password } = req.body;
      try {
        const user = await usersCollection.findOne({ email: email });
        if (!user) {
          return res.send({
            success: false,
            message: "User not found",
            data: [],
          });
        }
        bcrypt.compare(password, user.password, (err, result) => {
          if (!result) {
            return res.send({
              success: false,
              message: "Password not matched",
              data: [],
            });
          }

          const token = jwt.sign(
            { email: user.email },
            process.env.JWT_SECRET,
            {
              expiresIn: "365d",
            }
          );
          //   res.cookie("token", token, { httpOnly: true });
          res.send({ success: true, message: "Login successful", token });
        });
      } catch (error) {
        res.send({
          success: false,
          message: "something went wrong",
          error: error.message,
        });
      }
    });
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

// default
app.get("/", (req, res) => {
  res.send("Welcome to server");
});

app.listen(PORT, () => {
  console.log(`Server running at: http://localhost:${PORT}`);
});
