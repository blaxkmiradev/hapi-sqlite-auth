require('dotenv').config();
const Hapi = require('@hapi/hapi');
const JWT = require('@hapi/jwt');
const bcrypt = require('bcrypt');
const db = require('./db');

const init = async () => {
  const server = Hapi.server({
    port: 3000,
    host: 'localhost'
  });

  // JWT strategy
  await server.register(JWT);

  server.auth.strategy('jwt', 'jwt', {
    keys: process.env.JWT_SECRET,
    verify: {
      aud: false,
      iss: false,
      sub: false,
      maxAgeSec: 24 * 60 * 60
    },
    validate: (artifacts) => {
      return {
        isValid: true,
        credentials: { user: artifacts.decoded.payload }
      };
    }
  });

  server.auth.default('jwt');

  // REGISTER
  server.route({
    method: 'POST',
    path: '/register',
    options: { auth: false },
    handler: async (req) => {
      const { username, password } = req.payload;

      const hash = await bcrypt.hash(password, 10);

      try {
        db.prepare('INSERT INTO users (username, password) VALUES (?, ?)')
          .run(username, hash);

        return { message: 'User created' };
      } catch (err) {
        return { error: 'User exists' };
      }
    }
  });

  // LOGIN
  server.route({
    method: 'POST',
    path: '/login',
    options: { auth: false },
    handler: async (req) => {
      const { username, password } = req.payload;

      const user = db.prepare('SELECT * FROM users WHERE username = ?')
        .get(username);

      if (!user) return { error: 'Invalid user' };

      const valid = await bcrypt.compare(password, user.password);
      if (!valid) return { error: 'Wrong password' };

      const token = JWT.token.generate(
        { id: user.id, username: user.username },
        {
          key: process.env.JWT_SECRET,
          algorithm: 'HS256'
        }
      );

      return { token };
    }
  });

  // PROTECTED ROUTE
  server.route({
    method: 'GET',
    path: '/profile',
    handler: (req) => {
      return {
        message: 'Protected data',
        user: req.auth.credentials.user
      };
    }
  });

  await server.start();
  console.log('Server running on', server.info.uri);
};

init();
