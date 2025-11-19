require("dotenv").config();
const express = require("express");
const app = express();
const PORT = process.env.PORT || 3000;
const cors = require("cors");
const bcrypt = require("bcrypt");
const saltRounds = 10;
let jwt = require("jsonwebtoken");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const mongoUri = process.env.MONGO_URI;
// middlewares
app.use(
  cors({
    origin: [
      "http://localhost:5173",
      "https://smart-task-management-tau.vercel.app",
    ],
    credentials: true,
  })
);
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
    const tasksCollection = db.collection("tasks");
    const activitiesCollection = db.collection("activities");
    // middlewares
    const verifyToken = (req, res, next) => {
      const header = req?.headers?.authorization;
      if (!header || !header.startsWith("Bearer"))
        return res.status(401).send("Unauthorized access");
      const token = header.split(" ")[1];
      if (!token) return res.status(401).send("Unauthorized access");
      jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).send("Unauthorized access");
        if (decoded && decoded.email) {
          req.email = decoded.email;
          next();
        }
      });
    };
    // user verification
    app.get("/get-user", verifyToken, async (req, res) => {
      const email = req.email;
      try {
        const user = await usersCollection.findOne({ email });
        if (user) {
          res.send({
            success: true,
            message: "User found",
            data: { fullName: user.fullName, email: user.email },
          });
        } else {
          res.status(401).send("Unauthorized access");
        }
      } catch (error) {
        res.send({
          success: false,
          message: "Something went wrong",
          error: error.message,
        });
      }
    });
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
          res.send({
            success: true,
            message: "Login successful",
            token,
            data: user,
          });
        });
      } catch (error) {
        res.send({
          success: false,
          message: "something went wrong",
          error: error.message,
        });
      }
    });
    // create team
    app.post("/create-team", verifyToken, async (req, res) => {
      const { teamName, createdBy } = req.body;
      const createdAt = new Date().toISOString();
      try {
        const newTeam = await teamsCollection.insertOne({
          teamName,
          createdBy,
          members: [],
          createdAt,
        });
        if (newTeam.insertedId) {
          res.send({ success: true, message: "Team created", data: newTeam });
        } else {
          res.send({
            success: false,
            message: "Failed to create",
            data: newTeam,
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
    // get all teams
    app.get("/teams/:email", verifyToken, async (req, res) => {
      const { email } = req.params;
      try {
        const teams = await teamsCollection
          .find({ createdBy: email })
          .toArray();
        if (teams && teams.length > 0) {
          res.send({
            success: true,
            message: "Fetching successful",
            data: teams,
          });
        } else {
          res.send({ success: false, message: "No team found", data: [] });
        }
      } catch (error) {
        res.send({
          success: false,
          message: "Something went wrong",
          error: error.message,
        });
      }
    });
    // add member to team
    app.post("/add-member", verifyToken, async (req, res) => {
      const { memberTeam: teamId } = req.body;
      const member = req.body;
      try {
        const addMember = await teamsCollection.updateOne(
          { _id: new ObjectId(teamId) },
          {
            $push: {
              members: {
                name: member.memberName,
                role: member.memberRole,
                capacity: parseInt(member.memberCapacity),
              },
            },
          }
        );
        if (addMember.modifiedCount) {
          res.send({
            success: true,
            message: "Member successfully added",
            data: addMember,
          });
        } else {
          res.send({
            success: false,
            message: "Failed to add member",
            data: addMember,
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
    // create projects
    app.post("/create-project", verifyToken, async (req, res) => {
      const project = req.body;
      project.createdAt = new Date().toISOString();
      try {
        const createNewProject = await projectsCollection.insertOne(project);
        if (createNewProject.insertedId) {
          res.send({
            success: true,
            message: "Project created successfully",
            data: createNewProject,
          });
        } else {
          res.send({
            success: false,
            message: "Failed to create project",
            data: createNewProject,
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
    // get all projects
    app.get("/projects/:email", verifyToken, async (req, res) => {
      const { email } = req.params;
      try {
        const projects = await projectsCollection
          .find({ createdBy: email })
          .toArray();
        if (projects && projects.length > 0) {
          res.send({
            success: true,
            message: "Fetching successful",
            data: projects,
          });
        } else {
          res.send({
            success: false,
            message: "0 project found",
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
    // get members by team
    app.get("/members/:team", verifyToken, async (req, res) => {
      const { team } = req.params;
      try {
        const members = await teamsCollection.findOne(
          { teamName: team },
          { projection: { _id: 0, members: 1 } }
        );
        const arr = members.members;
        // console.log(arr);
        for (const member of arr) {
          const assignTasks = await tasksCollection
            .find({ assignMember: member.name, status: { $ne: "done" } })
            .toArray();
          const length = await assignTasks.length;
          member.currentTask = length;
        }
        if (members) {
          res.send({
            success: true,
            message: "Fetching successful",
            data: arr,
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
    // add task
    app.post("/add-task", verifyToken, async (req, res) => {
      const task = req.body;
      try {
        const newTask = await tasksCollection.insertOne({
          project: task.project,
          title: task.taskTitle,
          description: task.taskDescription,
          assignMember: task.assignMember,
          priority: task.taskPriority,
          status: "pending",
        });
        if (newTask.insertedId) {
          res.send({
            success: true,
            message: "Task added successfully",
            data: newTask,
          });
        } else {
          res.send({
            success: false,
            message: "Failed to add",
            data: newTask,
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

    // get all tasks
    app.get("/tasks/:email", verifyToken, async (req, res) => {
      try {
        const { email } = req.params;
        const projects = await projectsCollection
          .find({ createdBy: email }, { projection: { _id: 0, name: 1 } })
          .toArray();
        const projectsArr = projects.map((project) => project.name);
        const allTasks = await tasksCollection
          .find({ project: { $in: projectsArr } })
          .toArray();
        if (allTasks && allTasks.length > 0) {
          res.send({
            success: true,
            message: "Fetching successful",
            data: allTasks,
          });
        } else {
          res.send({ success: false, message: "0 task found", data: [] });
        }
      } catch (error) {
        res.send({
          success: false,
          message: "Something went wrong",
          error: error.message,
        });
      }
    });

    // delete a task
    app.delete("/delete-task/:deleteId", verifyToken, async (req, res) => {
      const { deleteId } = req.params;
      try {
        const deleteTask = await tasksCollection.deleteOne({
          _id: new ObjectId(deleteId),
        });
        if (deleteTask.deletedCount > 0) {
          res.send({
            success: true,
            message: "Deleted successfully",
            data: deleteTask,
          });
        } else {
          res.send({
            success: false,
            message: "Failed to delete",
            data: deleteTask,
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
    // change status
    app.patch("/update-task-status", verifyToken, async (req, res) => {
      try {
        const { id, status } = req.body;
        const updateTask = await tasksCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status: status } }
        );
        if (updateTask.modifiedCount > 0) {
          res.send({
            success: true,
            message: "Task status successfully updated",
            data: updateTask,
          });
        } else {
          res.send({
            success: false,
            message: "Failed to update",
            data: updateTask,
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
    // update task
    app.put("/update-task", verifyToken, async (req, res) => {
      const task = req.body;
      const query = { _id: new ObjectId(task?.taskId) };
      try {
        const updateTask = await tasksCollection.updateOne(query, {
          $set: {
            title: task.taskTitle,
            description: task.taskDescription,
            priority: task.taskPriority,
          },
        });
        if (updateTask.modifiedCount > 0) {
          res.send({
            success: true,
            message: "Task successfully updated",
            data: updateTask,
          });
        } else {
          res.send({
            success: false,
            message: "Failed to update",
            data: updateTask,
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

    //team summary
    app.get("/team-summary", verifyToken, async (req, res) => {
      try {
        const members = await teamsCollection
          .find({}, { projection: { _id: 0, members: 1 } })
          .toArray();
        const arr = members.map((member) => member.members);
        const flatArr = arr.flat();
        // task length
        for (const ar of flatArr) {
          const name = ar.name;
          const tasks = await tasksCollection
            .find({
              assignMember: name,
            })
            .toArray();
          const currentTask = tasks.length;
          ar.currentTask = currentTask;
          const teams = await teamsCollection.findOne(
            { "members.name": name },
            { projection: { _id: 0, teamName: 1 } }
          );
          ar.teamName = teams.teamName;
        }
        if (flatArr && flatArr.length > 0) {
          res.send({
            success: true,
            message: "Fetching successful",
            data: flatArr,
          });
        } else {
          res.send({
            success: false,
            message: "0 data found",
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
    // total projects and tasks
    app.get("/total/:email", verifyToken, async (req, res) => {
      try {
        const { email } = req.params;
        const projects = await projectsCollection
          .find({ createdBy: email }, { projection: { _id: 0, name: 1 } })
          .toArray();
        const projectsFinal = projects.map((project) => project.name);
        const projectLength = projectsFinal.length;
        let taskLength = 0;
        for (const final of projectsFinal) {
          const tasks = await tasksCollection
            .find({ project: final })
            .toArray();
          taskLength += tasks.length;
        }
        res.send({
          success: true,
          message: "Fetching successful",
          data: { projectLength, taskLength },
        });
      } catch (error) {
        res.send({
          success: false,
          message: "Something went wrong",
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
