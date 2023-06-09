const models = require("../db/db");
const express = require("express");
const data_router = express.Router();
const mysql = require("mysql2");

let conn = mysql.createConnection(models.mysql);
conn.connect();
conn.on("error", (err) => {
  console.log("Re-connecting lost conn: ");
  conn = mysql.createConnection(models.mysql);
});

// DATABASE CREATE
const crearBaseDeDatos = `CREATE DATABASE IF NOT EXISTS cena`;

conn.query(crearBaseDeDatos, (err, results, fields) => {
  if (err) {
    console.error("Error al crear la base de datos:", err);
    return;
  }
  console.log("Base de datos creada exitosamente o ya existe");
  
  // Conectar a la base de datos creada y crear las tablas
  conn.query(`USE cena`, (err, results, fields) => {
    if (err) {
      console.error("Error al conectar a la base de datos:", err);
      return;
    }
    
    // TABLA USUARIOS

    const crearTablaUsuario = `
    CREATE TABLE IF NOT EXISTS usuarios (
      id INT PRIMARY KEY AUTO_INCREMENT,
      username VARCHAR(50) NOT NULL UNIQUE,
      roles VARCHAR(50) NOT NULL,
      password VARCHAR(255) NOT NULL,
      nombre VARCHAR(50) NOT NULL,
      apellido VARCHAR(50) NOT NULL,
      edad INT NOT NULL,
      direccion VARCHAR(100) NOT NULL,
      poblacion VARCHAR(50) NOT NULL,
      provincia VARCHAR(50) NOT NULL,
      pais VARCHAR(50) NOT NULL,
      codigopostal INT NOT NULL,
      genero VARCHAR(50) NOT NULL,
      mobile INT NOT NULL
    );
    `;

    conn.query(crearTablaUsuario, (err, results, fields) => {
      if (err) {
        console.error("Tabla de usuario ya creada");
        return;
      }
      console.log("Tabla de usuarios creada exitosamente");
    });

    // TABLA USUARIOS INVITADOS

    const crearTablaUsuarioInvitado = `
    CREATE TABLE IF NOT EXISTS usuariosinvitados (
      id INT PRIMARY KEY AUTO_INCREMENT,
      id_usuario INT,
      id_concepto BIGINT
    );
    `;

    conn.query(crearTablaUsuarioInvitado, (err, results, fields) => {
      if (err) {
        console.error("Tabla de usuario invitado ya creada");
        return;
      }
      console.log("Tabla de lso usuarios invitados creada exitosamente");
    });

    // TABLA CONCEPTO

    const crearTablaConcepto = `
    CREATE TABLE IF NOT EXISTS concepto (
      id_concepto BIGINT PRIMARY KEY UNIQUE,
      estado BOOLEAN NOT NULL,
      id_usuario INT
    );
    `;

    conn.query(crearTablaConcepto, (err, results, fields) => {
      if (err) {
        console.error("Tabla de concepto ya creada");
        return;
      }
      console.log("Tabla de Concepto creada exitosamente");
    });

    // TABLA ARTICULOS

    const crearTablaArticulos = `
    CREATE TABLE IF NOT EXISTS articulos (
      id_articulo INT PRIMARY KEY AUTO_INCREMENT,
      nombre VARCHAR(100) NOT NULL,
      descripcion VARCHAR(255) NOT NULL,
      precio DECIMAL(10, 2) NOT NULL,
      archivo_imagen VARCHAR(100) NOT NULL
    );
    `;

    conn.query(crearTablaArticulos, (err, results, fields) => {
      if (err) {
        console.error("Tabla de articulos ya creada");
        return;
      }
      console.log("Tabla de Articulos creada exitosamente");
    });

    // TABLA CARRITO

    const crearTablaCarrito = `
    CREATE TABLE IF NOT EXISTS carrito (
      id_carrito INT PRIMARY KEY AUTO_INCREMENT,
      cantidad INT NOT NULL,
      id_concepto BIGINT,
      id_articulo INT,
      id_invitado INT
    );
    `;

    conn.query(crearTablaCarrito, (err, results, fields) => {
      if (err) {
        console.error("Tabla de carrito ya creada");
        return;
      }
      console.log("Tabla de Carrito creada exitosamente");
    });

    // CREAR LAS RELACIONES

    // relacion usuario > concepto
    const agregarRelacionUsuarioConcepto = `
    ALTER TABLE concepto
    ADD FOREIGN KEY (id_usuario) REFERENCES usuarios (id) ON DELETE CASCADE;
    `;

    conn.query(agregarRelacionUsuarioConcepto, (err, results, fields) => {
      if (err) {
        console.error(
          "Error al crear la Relacion Usuario-Conecepto: " + err.stack
        );
        return;
      }
      console.log("Relacion Tablas de Usuario-Conecepto creada exitosamente");
    });

    // relacion concepto > usuario invitado y usarios > usuario invitado
    const agregarRelacionsUsuariosInvitados = `
    ALTER TABLE usuariosinvitados
    ADD FOREIGN KEY (id_usuario) REFERENCES usuarios (id) ON DELETE CASCADE,
    ADD FOREIGN KEY (id_concepto) REFERENCES concepto (id_concepto) ON DELETE CASCADE;
    `;

    conn.query(agregarRelacionsUsuariosInvitados, (err, results, fields) => {
      if (err) {
        console.error(
          "Error al crear las Relacions Usuarios&Coneceptos-UsuariosInvitados: " + err.stack
        );
        return;
      }
      console.log("Relacion Tablas de Usuarios&Coneceptos-UsuariosInvitados creada exitosamente");
    });
    // relacion concpeto > carrito y articulos > carrito
    const agregarRelacionCarritoArticulos = `
    ALTER TABLE carrito
    ADD FOREIGN KEY (id_concepto) REFERENCES concepto (id_concepto) ON DELETE CASCADE,
    ADD FOREIGN KEY (id_invitado) REFERENCES usuariosinvitados (id) ON DELETE CASCADE,
    ADD FOREIGN KEY (id_articulo) REFERENCES articulos (id_articulo) ON DELETE CASCADE;
    `;

    conn.query(agregarRelacionCarritoArticulos, (err, results, fields) => {
      if (err) {
        console.error(
          "Error al crear la Relacion de Concepto&Articulos-Carrito: " + err.stack
        );
        return;
      }
      console.log("Relacion Tablas de Concepto&Articulos-Carrito creada exitosamente");
    });
  });
});

module.exports = data_router;
