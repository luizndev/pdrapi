const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dns = require("dns");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

const User = require("./models/User");
const Informatica = require("./models/Informatica");

// Open Route
app.get("/", (req, res) => {
  res.status(200).json({ message: "Bem vindo a api" });
});

// Rota para obter todos os registros
app.get("/informatica", checkToken, async (req, res) => {
  try {
    const informaticaRecords = await Informatica.find({});
    res.status(200).json(informaticaRecords);
  } catch (error) {
    res.status(500).json({ message: "Erro ao obter registros", error });
  }
});

// Rota para registrar um novo formulário
app.post("/informatica/register", async (req, res) => {
  const {
    professor,
    email,
    data,
    modalidade,
    alunos,
    laboratorio,
    software,
    equipamento,
    observacao,
    token,
    userID,
  } = req.body;

  if (
    !professor ||
    !email ||
    !data ||
    !modalidade ||
    !alunos ||
    !laboratorio ||
    !software ||
    !equipamento ||
    !observacao ||
    !token
  ) {
    return res.status(400).json({ message: "Preencha todos os campos" });
  }

  try {
    const registrosNoDia = await Informatica.countDocuments({ data });

    if (registrosNoDia >= 5) {
      return res
        .status(400)
        .json({ message: "Laboratório Esgotado para esse dia" });
    }

    const laboratorioExistente = await Informatica.findOne({
      data,
      laboratorio,
    });

    if (laboratorioExistente) {
      return res.status(400).json({
        message: "Laboratório já possui uma solicitação para esse dia",
      });
    }

    const informatica = new Informatica({
      professor,
      email,
      data,
      modalidade,
      alunos,
      laboratorio,
      software,
      equipamento,
      observacao,
      token,
      userID,
    });

    await informatica.save();
    res.status(201).json({ message: "Formulário registrado com sucesso" });
  } catch (error) {
    res.status(500).json({ message: "Erro ao registrar formulário" });
  }
});

// Nova rota para obter todas as solicitações na coleção
app.get("/auth/solicitacoes", checkToken, async (req, res) => {
  try {
    // Buscar todos os documentos na coleção "informaticas"
    const solicitacoes = await Informatica.find({});
    res.status(200).json(solicitacoes);
  } catch (error) {
    res.status(500).json({ message: "Erro ao obter as solicitações", error });
  }
});


const validDomains = ["kroton.com.br", "cogna.com.br"];

const isValidEmailFormat = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
};

const isDomainValid = (domain) => {
  return new Promise((resolve, reject) => {
    dns.resolveMx(domain, (err, addresses) => {
      if (err || addresses.length === 0) {
        resolve(false);
      } else {
        resolve(true);
      }
    });
  });
};

app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "Preencha todos os campos" });
  }

  if (password !== confirmpassword) {
    return res.status(400).json({ message: "As senhas não conferem" });
  }

  if (!isValidEmailFormat(email)) {
    return res.status(400).json({ message: "Formato de email inválido" });
  }

  const emailDomain = email.split("@")[1];
  if (!validDomains.includes(emailDomain)) {
    return res.status(400).json({
      message:
        "Por favor, utilize um email institucional (@kroton.com.br ou @cogna.com.br)",
    });
  }

  const isDomainValidResult = await isDomainValid(emailDomain);
  if (!isDomainValidResult) {
    return res
      .status(400)
      .json({ message: "O domínio do email não possui registros válidos" });
  }

  const userExists = await User.findOne({ email });
  if (userExists) {
    return res.status(400).json({ message: "Email já cadastrado" });
  }

  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({ message: "Usuário cadastrado com sucesso" });
  } catch (error) {
    res.status(500).json({ message: "Erro ao cadastrar" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Preencha todos os campos" });
  }

  const user = await User.findOne({ email });

  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado!" });
  }

  const checkPassword = await bcrypt.compare(password, user.password);
  if (!checkPassword) {
    return res.status(422).json({ message: "Senha incorreta" });
  }

  try {
    const secret = process.env.SECRET;
    const token = jwt.sign({ id: user._id }, secret);
    res
      .status(200)
      .json({ message: "Logado com sucesso", token, userId: user._id });
  } catch (error) {
    res.status(500).json({ message: "Erro ao logar" });
  }
});

app.get("/auth/:id", checkToken, async (req, res) => {
  const id = req.params.id;
  const user = await User.findById(id, "-password");

  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado" });
  }

  res.status(200).json({ user });
});

mongoose
  .connect(
    `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASS}@cluster0.8zd2dbs.mongodb.net/${process.env.MONGO_DATABASE}?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(80, () => {
      console.log("Servidor Ligado com sucesso.");
    });
  })
  .catch((err) => {
    console.log(err);
  });

function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Acesso negado" });
  }

  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret);
    next();
  } catch (error) {
    res.status(400).json({ message: "Token inválido!" });
  }
}
