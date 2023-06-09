const models = require("../db/db");
const express = require("express");
const controller_router = express.Router();
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const upload = multer();
const fs = require("fs");
const path = require("path");
const secretKey = "your_secret_key";

let conn = mysql.createConnection(models.mysql);
conn.connect();
conn.on("error", (err) => {
  console.log("Re-connecting lost conn: ");
  conn = mysql.createConnection(models.mysql);
});

// REGISTER

let isFirstUser = true; // Variable para controlar si es el primer usuario creado

controller_router.post("/user/register", (req, res) => {
  const newUser = req.body; // Datos del nuevo usuario proporcionados en el cuerpo de la solicitud

  // Verificar si hay usuarios existentes con el rol 'ROLE_ADMIN'
  conn.query(
    "SELECT COUNT(*) AS count FROM usuarios WHERE roles = 'ROLE_ADMIN'",
    (error, results) => {
      if (error) {
        console.error("Error al verificar usuarios existentes:", error);
        res
          .status(500)
          .json({ error: "Error al verificar usuarios existentes" });
      } else {
        const { count } = results[0];

        // Asignar el valor de 'roles' según si es el primer usuario, si hay usuarios con rol 'ROLE_ADMIN', o si no hay usuarios
        if (isFirstUser || count === 0) {
          newUser.roles = "ROLE_ADMIN";
        } else {
          newUser.roles = "ROLE_USER";
        }

        // Hashear la contraseña antes de almacenarla en la base de datos
        bcrypt.hash(newUser.password, 10, (hashError, hashedPassword) => {
          if (hashError) {
            console.error("Error al hashear la contraseña:", hashError);
            res.status(500).json({ error: "Error al registrar el usuario" });
          } else {
            newUser.password = hashedPassword;

            // Insertar el nuevo usuario en la tabla 'usuarios'
            conn.query(
              "INSERT INTO usuarios SET ?",
              newUser,
              (error, results) => {
                if (error) {
                  console.error("Error al registrar el usuario:", error);
                  res
                    .status(500)
                    .json({ message: "already exists" });
                } else {
                  console.log("Usuario registrado correctamente");
                  res
                    .status(200)
                    .json({ message: "Usuario registrado correctamente" });
                }
              }
            );
          }
        });
      }
    }
  );

  isFirstUser = false; // Actualizar el valor de isFirstUser después de registrar el primer usuario
});

// LOGIN

controller_router.post("/user/login", (req, res) => {
  const { username, password } = req.body;

  conn.query(
    "SELECT * FROM usuarios WHERE username = ?",
    username,
    (error, results) => {
      if (error) {
        console.error("Error al buscar el usuario:", error);
        res.status(500).json({ error: "Error al iniciar sesión" });
      } else {
        if (results.length === 0) {
          res.status(401).json({ error: "Credenciales inválidas" });
        } else {
          const user = results[0];
          const hashedPassword = user.password;

          bcrypt.compare(password, hashedPassword, (compareError, isMatch) => {
            if (compareError) {
              console.error("Error al comparar contraseñas:", compareError);
              res.status(500).json({ error: "Error al iniciar sesión" });
            } else if (!isMatch) {
              res.status(401).json({ error: "Credenciales inválidas" });
            } else {
              // Las credenciales son válidas, generar y devolver el token de autenticación
              const tokenPayload = {
                id: user.id,
                username: user.username,
                role: user.roles,
                // Puedes incluir cualquier otra información relevante del usuario en el token
              };
              const token = jwt.sign(tokenPayload, secretKey, {
                expiresIn: "1h",
              }); // Generar el token con una vigencia de 1 hora

              res.json({ token: token }); // Enviar el token como respuesta
            }
          });
        }
      }
    }
  );
});

// GENERAR TOKEN Y FUNCION PARA VALIDAR
function authenticateToken(req, res, next) {
  // Obtener el token de la cabecera de autorización
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Acceso no autorizado" });
  }

  // Verificar el token
  jwt.verify(token, secretKey, (error, decoded) => {
    if (error) {
      console.error("Error al verificar el token:", error);
      return res.status(403).json({ error: "Token inválido" });
    }

    // El token es válido, almacenar los datos del usuario en el objeto de solicitud para su uso posterior
    req.user = decoded;
    next();
  });
}

// Obtener todos los usuaios
controller_router.get("/user/clientes", authenticateToken, (req, res) => {
  // Obtener todos los datos de la tabla 'usuarios'
  conn.query("SELECT * FROM usuarios", (error, results) => {
    if (error) {
      console.error("Error al obtener los datos de los usuarios:", error);
      res
        .status(500)
        .json({ error: "Error al obtener los datos de los usuarios" });
    } else {
      console.log("Datos de usuarios obtenidos correctamente");
      res.status(200).json(results);
    }
  });
});

// Obtener Usuario por ID 
controller_router.get("/user/clientes/:id", authenticateToken, (req, res) => {
  const clientId = req.params.id;

  conn.query(
    "SELECT * FROM usuarios WHERE id = ?",
    [clientId],
    (error, results) => {
      if (error) {
        console.error("Error al buscar el usuario:", error);
        res.status(500).json({ error: "Error al obtener el usuario" });
      } else {
        if (results.length === 0) {
          // El usuario no existe
          res.status(404).json({ error: "Usuario no encontrado" });
        } else {
          console.log("Usuario encontrado correctamente");
          res.status(200).json(results[0]);
        }
      }
    }
  );
});

// Obtener Usuario admin
controller_router.get("/user/admin", authenticateToken, (req, res) => {

  conn.query(
    'SELECT nombre, apellido, direccion, poblacion,provincia, codigopostal, mobile FROM usuarios WHERE roles = "ROLE_ADMIN"',
    (error, results) => {
      if (error) {
        console.error("Error al buscar el usuario:", error);
        res.status(500).json({ error: "Error al obtener el usuario" });
      } else {
        if (results.length === 0) {
          // El usuario no existe
          res.status(404).json({ error: "Usuario no encontrado" });
        } else {
          console.log("Usuario encontrado correctamente");
          res.status(200).json(results[0]);
        }
      }
    }
  );
});

// Actualizar un cliente por ID
controller_router.put("/user/update/:id", authenticateToken, (req, res) => {
  const clientId = req.params.id;
  const {
    nombre,
    apellido,
    edad,
    direccion,
    poblacion,
    provincia,
    pais,
    codigopostal,
    genero,
    mobile,
  } = req.body; // Nuevos datos del cliente

  // Construir objeto con los campos actualizados
  const updatedFields = {};
  if (nombre) updatedFields.nombre = nombre;
  if (apellido) updatedFields.apellido = apellido;
  if (edad) updatedFields.edad = edad;
  if (direccion) updatedFields.direccion = direccion;
  if (poblacion) updatedFields.poblacion = poblacion;
  if (provincia) updatedFields.provincia = provincia;
  if (pais) updatedFields.pais = pais;
  if (codigopostal) updatedFields.codigopostal = codigopostal;
  if (genero) updatedFields.genero = genero;
  if (mobile) updatedFields.mobile = mobile;

  conn.query(
    "UPDATE usuarios SET ? WHERE id = ?",
    [updatedFields, clientId],
    (error, results) => {
      if (error) {
        console.error("Error al actualizar el cliente:", error);
        res.status(500).json({ error: "Error al actualizar el cliente" });
      } else {
        if (results.affectedRows === 0) {
          // El cliente no existe
          res.status(404).json({ error: "Cliente no encontrado" });
        } else {
          console.log("Cliente actualizado correctamente");
          res
            .status(200)
            .json({ message: "Cliente actualizado correctamente" });
        }
      }
    }
  );
});

// Borrar un cliente por ID
controller_router.delete("/user/delete/:id", authenticateToken, (req, res) => {
  const clientId = req.params.id;

  conn.query(
    "DELETE FROM usuarios WHERE id = ?",
    [clientId],
    (error, results) => {
      if (error) {
        console.error("Error al borrar el cliente:", error);
        res.status(500).json({ error: "Error al borrar el cliente" });
      } else {
        if (results.affectedRows === 0) {
          // El cliente no existe
          res.status(404).json({ error: "Cliente no encontrado" });
        } else {
          console.log("Cliente borrado correctamente");
          res.status(200).json({ message: "Cliente borrado correctamente" });
        }
      }
    }
  );
});


const checkAdminRole = (req, res, next) => {
  // Verificar el rol del usuario almacenado en req.user.role
  if (req.user.role !== 'ROLE_ADMIN') {
    res.status(403).json({ error: "Acceso denegado. Permiso de administrador requerido." });
    return;
  }
  next();
};

// Dar Alta al articulos
controller_router.post("/articulos/add", upload.none(), authenticateToken, checkAdminRole, (req, res) => {
  const { 
    nombre,
    descripcion, 
    precio, 
    archivo_imagen, 
    file
  }= req.body;
  const base64Data = file.replace(/^data:image\/\w+;base64,/, "");
  const imagePath = `./api/images/${archivo_imagen}`;

  fs.writeFile(imagePath, base64Data, { encoding: "base64" }, (err) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error:"Error al guardar la imagen" });
    } else {
      conn.query('INSERT INTO articulos SET ?', {nombre, descripcion, precio, archivo_imagen}, (error, results, fields) => {
        if (error) {
          console.log("Error al agregar el artículo:", error);
          res.status(500).json({ error: "Error al agregar el artículo" });
        } else {
          console.log("Artículo agregado exitosamente");
          res.status(200).json({ message: "Artículo agregado exitosamente" });
        }
      });
    }
  });
});

// Obtener todos los artículos
controller_router.get("/articulos/", authenticateToken, (req, res) => {
    conn.query("SELECT * FROM articulos", (error, results, fields) => {
      if (error) {
        console.log("Error al obtener los artículos:", error);
        res.status(500).json({ error: "Error al obtener los artículos" });
      } else {
        console.log("Artículos obtenidos exitosamente");
        
        // Iterar sobre los resultados y agregar la URL de la imagen al objeto del artículo
        const artiulosConImagenes = results.map((articulo) => {
          const imagenURL = `http://localhost:8000/api/images/${articulo.archivo_imagen}`;
          return { ...articulo, imagenURL };
        });
  
        res.status(200).json(artiulosConImagenes);
      }
    });
});

// Obtener artículo por ID
controller_router.get("/articulos/:id", authenticateToken, (req, res) => {
    const articulId = req.params.id;
    conn.query("SELECT * FROM articulos WHERE id_articulo = ?", [articulId], (error, results, fields) => {
      if (error) {
        console.log("Error al obtener el artículo:", error);
        res.status(500).json({ error: "Error al obtener el artículo" });
      } else if (results.length === 0) {
        console.log("Artículo no encontrado");
        res.status(404).json({ error: "Artículo no encontrado" });
      } else {
        console.log("Artículo obtenido exitosamente");
        const articulo = results[0];
        const imagenURL = `http://localhost:8000/api/images/${articulo.archivo_imagen}`;
        const articuloConImagen = { ...articulo, imagenURL };
        res.status(200).json(articuloConImagen);
      }
    });
  });

// Obtenir Imagenes
const allowedExtensions = [".png", ".jpg", ".jpeg"]; // Extensiones de archivo permitidas

controller_router.get("/images/:archivo_imagen",  (req, res) => {
  const archivo_imagen = req.params.archivo_imagen;
  const fileExtension = path.extname(archivo_imagen);

  // Validar la extensión del archivo
  if (!allowedExtensions.includes(fileExtension)) {
    res.status(400).json({ error: "Formato de imagen no válido" });
    return;
  }

  const filePath = path.join(__dirname, "./images", archivo_imagen);

  // Establecer el tipo de contenido según la extensión del archivo
  let contentType = "";
  if (fileExtension === ".png") {
    contentType = "image/png";
  } else if (fileExtension === ".jpg" || fileExtension === ".jpeg") {
    contentType = "image/jpeg";
  }

  // Enviar la imagen como respuesta con el tipo de contenido adecuado
  res.sendFile(
    filePath,
    {
      headers: {
        "Content-Type": contentType,
      },
    },
    (error) => {
      if (error) {
        console.log("Error al enviar la imagen:", error);
        res.status(500).json({ error: "Error al enviar la imagen" });
      }
    }
  );
});

// Actualizar un artículo por ID
controller_router.put("/articulos/update/:id", authenticateToken, checkAdminRole, upload.none(), (req, res) => {
  const articulId = req.params.id;
  const { 
      nombre,
      descripcion, 
      precio, 
      archivo_imagen, 
      file 
  } = req.body; // Nuevos datos del artículo

  // Construir objeto con los campos actualizados
  const updatedFields = {};
  if (nombre) updatedFields.nombre = nombre;
  if (descripcion) updatedFields.descripcion = descripcion;
  if (precio) updatedFields.precio = precio;

  if (archivo_imagen && file) {
    // Procesar la imagen solo si se proporciona una nueva
    const base64Data = file.replace(/^data:image\/\w+;base64,/, "");
    const imagePath = `./api/images/${archivo_imagen}`;

    fs.writeFile(imagePath, base64Data, { encoding: "base64" }, (err) => {
      if (err) {
        console.error(err);
        res.status(500).json({ error: "Error al guardar la imagen" });
      } else {
        updatedFields.archivo_imagen = archivo_imagen;
        updateArticle();
      }
    });
  } else {
    // No se proporcionó una nueva imagen, actualizar otros campos
    updateArticle();
  }

  function updateArticle() {
    conn.query(
      "UPDATE articulos SET ? WHERE id_articulo = ?",
      [updatedFields, articulId],
      (error, results) => {
        if (error) {
          console.error("Error al actualizar el artículo:", error);
          res.status(500).json({ error: "Error al actualizar el artículo" });
        } else {
          if (results.affectedRows === 0) {
            // El artículo no existe
            res.status(404).json({ error: "Artículo no encontrado" });
          } else {
            console.log("Artículo actualizado correctamente");
            res.status(200).json({ message: "Artículo actualizado correctamente" });
          }
        }
      }
    );
  }
});


// Borrar todo los articulos
controller_router.delete("/articulos/delete", authenticateToken, checkAdminRole, (req, res) => {
  conn.query("SELECT archivo_imagen FROM articulos", (error, results) => {
    if (error) {
      console.error("Error al obtener las imágenes de los artículos:", error);
      res.status(500).json({ error: "Error al borrar los artículos" });
    } else {
      const imagenes = results.map((articulo) => articulo.archivo_imagen);

      // Eliminar las imágenes del servidor
      imagenes.forEach((imagen) => {
        const imagePath = path.join(__dirname, "./images", imagen);
        fs.unlink(imagePath, (err) => {
          if (err) {
            console.error("Error al borrar la imagen:", err);
          } else {
            console.log(`Imagen ${imagen} borrada exitosamente`);
          }
        });
      });

      // Eliminar los artículos de la base de datos
      conn.query("DELETE FROM articulos", (error, results) => {
        if (error) {
          console.error("Error al borrar los artículos:", error);
          res.status(500).json({ error: "Error al borrar los artículos" });
        } else {
          console.log("Artículos borrados exitosamente");
          res.status(200).json({ message: "Artículos borrados exitosamente" });
        }
      });
    }
  });
});

// Borrar un artículo por ID
controller_router.delete("/articulos/delete/:id", authenticateToken, checkAdminRole, (req, res) => {
  const articulId = req.params.id;

  conn.query("SELECT archivo_imagen FROM articulos WHERE id_articulo = ?", [articulId], (error, results) => {
    if (error) {
      console.error("Error al obtener la imagen del artículo:", error);
      res.status(500).json({ error: "Error al borrar el artículo" });
    } else if (results.length === 0) {
      res.status(404).json({ error: "Artículo no encontrado" });
    } else {
      const imagen = results[0].archivo_imagen;

      // Eliminar la imagen del servidor
      const imagePath = path.join(__dirname, "./images", imagen);
      fs.unlink(imagePath, (err) => {
        if (err) {
          console.error("Error al borrar la imagen:", err);
        } else {
          console.log(`Imagen ${imagen} borrada exitosamente`);

          // Eliminar el artículo de la base de datos
          conn.query("DELETE FROM articulos WHERE id_articulo = ?", [articulId], (error, results) => {
            if (error) {
              console.error("Error al borrar el artículo:", error);
              res.status(500).json({ error: "Error al borrar el artículo" });
            } else if (results.affectedRows === 0) {
              res.status(404).json({ error: "Artículo no encontrado" });
            } else {
              console.log("Artículo borrado exitosamente");
              res.status(200).json({ message: "Artículo borrado exitosamente" });
            }
          });
        }
      });
    }
  });
});


// Crear el id de Concepto 
controller_router.post("/concepto/crear", authenticateToken, (req, res) => {
  const { id_concepto, id_usuario } = req.body;

  // Verificar si el id_concepto ya existe en la tabla concepto
  conn.query('SELECT * FROM concepto WHERE id_concepto = ?', [id_concepto], (error, results) => {
    if (error) {
      console.error('Error al verificar el id_concepto:', error);
      res.status(500).json({ error: 'Ocurrió un error al verificar el id_concepto' });
    } else if (results.length > 0) {
      res.status(400).json({ error: 'El id_concepto ya existe' });
    } else {
      // Verificar si el usuario existe en la tabla usuarios
      conn.query('SELECT * FROM usuarios WHERE id = ?', [id_usuario], (error, results) => {
        if (error) {
          console.error('Error al verificar el usuario:', error);
          res.status(500).json({ error: 'Ocurrió un error al verificar el usuario' });
        } else if (results.length === 0) {
          res.status(400).json({ error: 'El usuario no existe' });
        } else {
          // Insertar el nuevo concepto con el estado predeterminado y el id_concepto proporcionado
          conn.query('INSERT INTO concepto (id_concepto, estado, id_usuario) VALUES (?, ?, ?)', [id_concepto, false, id_usuario], (error, results) => {
            if (error) {
              console.error('Error al crear el concepto:', error);
              res.status(500).json({ error: 'Ocurrió un error al crear el concepto' });
            } else {
              console.log("Concepto agregado exitosamente");
              res.status(200).json({ message: 'Concepto creado exitosamente' });
            }
          });
        }
      });
    }
  });
});

// Obtenir todos los conceptos
 controller_router.get('/concepto/', authenticateToken, (req, res) => {
  conn.query('SELECT * FROM concepto', (error, results, fields) => {
    if (error) {
      console.error('Error al obtener los conceptos:', error);
      res.status(500).json({ error: 'Ocurrió un error al obtener los conceptos' });
    } else {
      console.log("Conceptos obtenidos exitosamente");
      res.status(200).json(results);
    }
  });
}); 
// Obtenir concepto por ID
controller_router.get('/concepto/:id', authenticateToken, (req, res) => {
  const conceptoId = req.params.id;
  conn.query('SELECT * FROM concepto WHERE id_concepto = ?', [conceptoId], (error, results, fields) => {
    if (error) {
      console.log("Error al obtener el concepto:", error);
      res.status(500).json({ error: "Error al obtener el concepto" });
    } else if (results.length === 0) {
      console.log("concepto no encontrado");
      res.status(404).json({ error: "concepto no encontrado" });
    } else {
      console.log("Concepto obtenido exitosamente");
      res.status(200).json(results[0]);
    }
  });
});
// Obtener los clientes Invitados
controller_router.get("/usuariosinvitados/:id", authenticateToken, (req, res) => {
  const id = req.params.id;
  conn.query( 'SELECT * FROM usuariosinvitados WHERE id = ?', [id], (error, results, fields) => {
      if (error) {
        console.log("Error al obtener los clientes de la tabla usuariosinvitados:", error);
        res.status(500).json({ error: 'Error al obtener los clientes de la tabla usuariosinvitados' });
      } else if (results.length === 0) {
        console.log("Usuario no encontrado");
        res.status(404).json({ error: "Usuario no encontrado" });
      } else {
        console.log("Usuario Invitado obtenido exitosamente");
        res.status(200).json(results[0]);
      }
    }
  );
});

// agregar el usuario Invitado con id de Concepto introducido al tabla usuariosinvitados
controller_router.post("/usuariosinvitados/add", authenticateToken, (req, res) => {
  const { id_usuario, id_concepto } = req.body;

  // Verificar si el id_concepto existe en la tabla concepto
  conn.query('SELECT * FROM concepto WHERE id_concepto = ?', [id_concepto], (error, conceptoResults) => {
    if (error) {
      console.error('Error al verificar el id_concepto:', error);
      res.status(500).json({ error: 'Ocurrió un error al verificar el id_concepto' });
    } else if (conceptoResults.length === 0) {
      res.status(400).json({ error: 'El id_concepto no existe' });
    } else {
      // Verificar si el usuario existe en la tabla usuarios
      conn.query('SELECT * FROM usuarios WHERE id = ?', [id_usuario], (error, usuarioResults) => {
        if (error) {
          console.error('Error al verificar el usuario:', error);
          res.status(500).json({ error: 'Ocurrió un error al verificar el usuario' });
        } else if (usuarioResults.length === 0) {
          res.status(400).json({ error: 'El usuario no existe' });
        } else {
          // Verificar si el usuario ya está insertado con el mismo concepto
          conn.query('SELECT * FROM usuariosinvitados WHERE id_usuario = ? AND id_concepto = ?', [id_usuario, id_concepto], (error, invitadosResults) => {
            if (error) {
              console.error('Error al verificar el usuario invitado:', error);
              res.status(500).json({ error: 'Ocurrió un error al verificar el usuario invitado' });
            } else if (invitadosResults.length > 0) {
              const InvitadoId = invitadosResults[0].id;
              res.status(200).json({ id: InvitadoId, message: 'El usuario ya está invitado con el mismo concepto' });
            } else {
              // Insertar el nuevo usuario invitado 
              conn.query('INSERT INTO usuariosinvitados (id_usuario, id_concepto) VALUES (?, ?)', [id_usuario, id_concepto], (error, insertResults) => {
                if (error) {
                  console.error('Error al agregar el usuario a la tabla de invitados:', error);
                  res.status(500).json({ error: 'Ocurrió un error al agregar el usuario a la tabla de invitados' });
                } else {
                  const nuevoInvitadoId = insertResults.insertId;
                  console.log("Usuario agregado exitosamente a la tabla de invitados");
                  res.status(200).json({ id: nuevoInvitadoId, message: 'Usuario agregado exitosamente a la tabla de invitados' });
                }
              });
            }
          });
        }
      });
    }
  });
});



// Añadir Articulos al Carrito
controller_router.post("/carrito/add", authenticateToken, (req, res) => {
  const { cantidad, id_concepto, id_articulo, id_invitado } = req.body;

  if (id_invitado !== null) {
    // Actualizar registros con id_invitado no nulo
    const updateQuery = 'UPDATE carrito SET cantidad = ? WHERE id_concepto = ? AND id_articulo = ? AND id_invitado = ?';
    const updateValues = [cantidad, id_concepto, id_articulo, id_invitado];

    conn.query(updateQuery, updateValues, (error, updateResult) => {
      if (error) {
        console.log("Error al actualizar el artículo en el carrito:", error);
        res.status(500).json({ error: 'Error al actualizar el artículo en el carrito' });
      } else {
        if (updateResult.affectedRows > 0) {
          console.log("El artículo actualizado exitosamente en el carrito");
          res.status(200).json({ id_articulo, cantidad, id_concepto, message: "El artículo actualizado exitosamente en el carrito" });
        } else {
          // El registro no existe, realizar inserción
          const insertQuery = 'INSERT INTO carrito SET ?';
          const insertValues = { cantidad, id_concepto, id_articulo, id_invitado };

          conn.query(insertQuery, insertValues, (error, insertResult) => {
            if (error) {
              console.log("Error al agregar el artículo al carrito:", error);
              res.status(500).json({ error: 'Error al agregar el artículo al carrito' });
            } else {
              const newItemId = insertResult.insertId;
              console.log("El artículo agregado exitosamente al carrito");
              res.status(200).json({ id: newItemId, id_articulo, cantidad, id_concepto, message: "El artículo agregado exitosamente al carrito" });
            }
          });
        }
      }
    });
} else {
    // Actualizar registros con id_invitado nulo
    const updateQuery = 'UPDATE carrito SET cantidad = ? WHERE id_concepto = ? AND id_articulo = ? AND id_invitado IS NULL';
    const updateValues = [cantidad, id_concepto, id_articulo];

    conn.query(updateQuery, updateValues, (error, updateResult) => {
      if (error) {
        console.log("Error al actualizar el artículo en el carrito:", error);
        res.status(500).json({ error: 'Error al actualizar el artículo en el carrito' });
      } else {
        if (updateResult.affectedRows > 0) {
          console.log("El artículo actualizado exitosamente en el carrito");
          res.status(200).json({ id_articulo, cantidad, id_concepto, message: "El artículo actualizado exitosamente en el carrito" });
        } else {
          // El registro no existe, realizar inserción
          const insertQuery = 'INSERT INTO carrito SET ?';
          const insertValues = { cantidad, id_concepto, id_articulo, id_invitado };

          conn.query(insertQuery, insertValues, (error, insertResult) => {
            if (error) {
              console.log("Error al agregar el artículo al carrito:", error);
              res.status(500).json({ error: 'Error al agregar el artículo al carrito' });
            } else {
              const newItemId = insertResult.insertId;
              console.log("El artículo agregado exitosamente al carrito");
              res.status(200).json({ id: newItemId, id_articulo, cantidad, id_concepto, message: "El artículo agregado exitosamente al carrito" });
            }
          });
        }
      }
    });
  }
});

// Obtener los artículos del carrito 
controller_router.get("/carrito/:id_concepto", authenticateToken, (req, res) => {
  const id_concepto = req.params.id_concepto; // Obtén el id_concepto del cliente desde los parámetros de la ruta

  conn.query(
    "SELECT carrito.id_carrito, carrito.cantidad, carrito.id_invitado, articulos.* FROM carrito JOIN articulos ON carrito.id_articulo = articulos.id_articulo WHERE carrito.id_concepto = ?",
    [id_concepto],
    (error, results) => {
      if (error) {
        console.log("Error al obtener los artículos del carrito:", error);
        res.status(500).json({ error: 'Error al obtener los artículos del carrito' });
      } else {
        const id_invitado = results[0].id_invitado; // Obtén la ID de invitado del primer resultado de la consulta
        res.json({ id_concepto, id_invitado, results });
      }
    }
  );
});


// Ver los artículos añadidos por cada usuario invitado en un concepto específico
controller_router.get("/carrito/:id_concepto/:id_invitado", authenticateToken, (req, res) => {
  const id_concepto = req.params.id_concepto; // Obtén el id_concepto desde los parámetros de la ruta
  const id_invitado = req.params.id_invitado;

  conn.query(
    "SELECT usuariosinvitados.id_usuario, carrito.id_carrito, carrito.cantidad, articulos.* FROM usuariosinvitados JOIN carrito ON usuariosinvitados.id_concepto = carrito.id_concepto AND usuariosinvitados.id = carrito.id_invitado JOIN articulos ON carrito.id_articulo = articulos.id_articulo WHERE carrito.id_concepto = ? AND carrito.id_invitado = ?",
    [id_concepto, id_invitado],
    (error, results) => {
      if (error) {
        console.log("Error al obtener los artículos añadidos por los usuarios invitados:", error);
        res.status(500).json({ error: 'Error al obtener los artículos añadidos por los usuarios invitados' });
      } else {
        const data = {
          id_invitado: id_invitado,
          results: results
        };
        res.json(data);
      }
    }
  );
});
// Actualizar la cantidad de un artículo en el carrito
controller_router.put("/carrito/:id_carrito", authenticateToken, (req, res) => {
  const id_carrito = req.params.id_carrito; // Obtén el id_carrito desde los parámetros de la ruta
  const { cantidad } = req.body; // Obtén la nueva cantidad desde el cuerpo de la solicitud

  conn.query(
    "UPDATE carrito SET cantidad = ? WHERE id_carrito = ?",
    [cantidad, id_carrito],
    (error, updateResult) => {
      if (error) {
        console.log("Error al actualizar la cantidad del artículo en el carrito:", error);
        res.status(500).json({ error: 'Error al actualizar la cantidad del artículo en el carrito' });
      } else {
        if (updateResult.affectedRows > 0) {
          console.log("La cantidad del artículo actualizada exitosamente en el carrito");
          res.status(200).json({ id_carrito, cantidad, message: "La cantidad del artículo actualizada exitosamente en el carrito" });
        } else {
          console.log("No se encontró el artículo en el carrito");
          res.status(404).json({ error: 'No se encontró el artículo en el carrito' });
        }
      }
    }
  );
});

// Eliminar un artículo del carrito
controller_router.delete("/carrito/:id_carrito", authenticateToken, (req, res) => {
  const id_carrito = req.params.id_carrito; // Obtén el id_carrito desde los parámetros de la ruta

  conn.query(
    "DELETE FROM carrito WHERE id_carrito = ?",
    [id_carrito],
    (error, deleteResult) => {
      if (error) {
        console.log("Error al eliminar el artículo del carrito:", error);
        res.status(500).json({ error: 'Error al eliminar el artículo del carrito' });
      } else {
        if (deleteResult.affectedRows > 0) {
          console.log("El artículo ha sido eliminado exitosamente del carrito");
          res.status(200).json({ id_carrito, message: "El artículo ha sido eliminado exitosamente del carrito" });
        } else {
          console.log("No se encontró el artículo en el carrito");
          res.status(404).json({ error: 'No se encontró el artículo en el carrito' });
        }
      }
    }
  );
});

// Actualizar el estado de un concepto
controller_router.put("/concepto/:id_concepto", authenticateToken, (req, res) => {
  const id_concepto = req.params.id_concepto; 
  const { estado } = req.body;

  conn.query(
    "UPDATE concepto SET estado = ? WHERE id_concepto = ?",
    [estado, id_concepto],
    (error, updateResult) => {
      if (error) {
        console.log("Error al actualizar el estado del concepto:", error);
        res.status(500).json({ error: 'Error al actualizar el estado del concepto' });
      } else {
        if (updateResult.affectedRows > 0) {
          console.log("El estado del concepto actualizada exitosamente ");
          res.status(200).json({ id_concepto, estado, message: "El estado del concepto actualizada exitosamente" });
        } else {
          console.log("No se encontró el concepto");
          res.status(404).json({ error: 'No se encontró concepto' });
        }
      }
    }
  );
});
module.exports = controller_router;
