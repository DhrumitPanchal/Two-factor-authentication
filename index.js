import express from "express";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";

const app = express();
const PORT = 8000;
const userData = {};
const challengeStore = {};
const loginChallengeStore = {};

app.use(express.json());
app.use(express.static("./public"));

app.get("/", (req, res) => {
  return res.end("api is running...");
});

app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      return res.status(404).json({ message: "all details required" });
    }

    const id = `${Date.now()}`;
    const user = {
      id,
      email,
      password,
    };
    userData[id] = user;

    console.log(userData);
    return res
      .status(200)
      .json({ message: "register successfully", user: user });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "server error", error: error.message });
  }
});

app.post("/register-challenge", async (req, res) => {
  const { userID } = req.body;
  const user = userData[userID];
  try {
    const challengePayload = await generateRegistrationOptions({
      rpID: "localhost",
      rpName: "my local host machine",
      userName: user?.email,
    });

    challengeStore[userID] = challengePayload.challenge;
    return res
      .status(200)
      .json({ message: "register successfully", options: challengePayload });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "server error", error: error.message });
  }
});

app.post("/verify-register-challenge", async (req, res) => {
  const { userID, challenge } = req.body;

  try {
    const verify = await verifyRegistrationResponse({
      response: challenge,
      expectedChallenge: challengeStore[userID],
      rpID: "localhost",
      rpName: "my local host machine",
      expectedOrigin: "http://localhost:8000",
    });

    if (!verify.verified) {
      return res.status(400).json({ message: "could not verified" });
    }

    userData[userID].publickey = verify.registrationInfo;

    console.log(userData[userID]);
    return res.status(200).json({ message: "verified successfully" });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "server error", error: error.message });
  }
});

app.post("/login-challenge", async (req, res) => {
  const { userID } = req.body;
  try {
    const options = await generateAuthenticationOptions({
      rpID: "localhost",
    });

    loginChallengeStore[userID] = options.challenge;
    return res.status(200).json({ options });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "server error", error: error.message });
  }
});

app.post("/verify-login-challenge", async (req, res) => {
  const { userID, challenge } = req.body;
  const user = userData[userID];
  console.log("login verify User :  ---------------");

  console.log(userData);
  try {
    const result = await verifyAuthenticationResponse({
      expectedChallenge: loginChallengeStore[userID],
      rpID: "localhost",
      expectedOrigin: "http://localhost:8000",
      response: challenge,
      authenticator: user.publickey,
    });

    console.log("check verify result : ---------------");
    console.log(result);
  } catch (error) {
    console.log(error);
    return res
      .status(500)
      .json({ message: "server error", error: error.message });
  }
});

app.listen(PORT, () => console.log("server running on port " + PORT));
