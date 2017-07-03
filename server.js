var express = require('express');
var app = express();
var bodyParser = require('body-parser');

var jwt = require('jsonwebtoken');
var config = require('./config');
var SECRET = 'someSecret';

var connect = require('./dbconnection');
var port = process.env.PORT || 8080;
app.set('secret', config.secret);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));

// an instance of the router for api routes
var router = express.Router();

//region Users API
// Login user
router.route('/login')
    .post(function (req, res) {

        var email = req.body.email;
        var password = req.body.passw;

        connect.query('SELECT * FROM users WHERE email=?', email, function (err, users) {

            if (err) throw err;

            var user = users[0];

            if (!user) {
                res.json({Body: {success: false, message: 'Authentication failed. User not found.'}});
            }
            else {
                if (user.password !== password) {
                    res.status(422, "Unprocessable Entity");
                    res.json({Body: {field: "password", message: "Wrong email or password"}});
                }
                else {
                    var token = jwt.sign({id: user.uid}, app.get('secret'), {
                        expiresIn: '3h' // expires in 3 hours
                    });

                    res.status(200, "OK");
                    res.json({token: token});
                }
            }
        });
    });

// Register user
router.route('/register')
    .post(function (req, res) {

        var name = req.body.name;
        var email = req.body.email;
        var password = req.body.passw;
        var phone = req.body.phone;

        connect.query('SELECT * FROM users WHERE email=?', email, function (err, users) {
            if (err) throw err;

            var user = users[0];

            if (user) {
                res.json({Body: {success: false, message: 'User already exist'}});
            }

            else {

                var sql = 'INSERT INTO users SET ?';
                var value = {username: name, email: email, password: password, phone: phone};

                connect.query(sql, value, function (err, result) {
                    if (err) throw err;

                    var token = jwt.sign({id: result.insertId}, app.get('secret'), {
                        expiresIn: '3h' // expires in 3 hours
                    });

                    res.status(200, "OK");
                    res.json({token: token});
                })
            }
        });

    });

// Route middleware to verify a token
router.use(function (req, res, next) {

    // check header or url parameters or post parameters for token
    var token = req.body.token || req.query.token || req.headers['x-access-token'] || req.headers['authorization'];

    // decode token
    if (token) {
        jwt.verify(token, app.get('secret'), function (err, decoded) {
            if (err) {
                res.json({success: false, message: 'Failed to authenticate token.'});
            }
            else {
                req.decoded = decoded;
                next();
            }
        });
    }
    else {
        // If no token then return error
        res.status(403).send({
            success: false,
            message: 'No token provided.'
        });
    }
});

// Get information about the current user
router.route('/me')
    .get(function (req, res) {

        var userId = req.decoded.id;

        connect.query('SELECT * FROM users WHERE uid = ?', userId, function (err, users) {
            if (err) throw err;

            var user = users[0];

            if (user) {
                res.status(200, 'OK');
                res.json(
                    {
                        'id': user.uid,
                        'phone': user.phone,
                        'name': user.username,
                        'email': user.email
                    });
            }
            else {
                res.status(401, 'Unauthorized');
                res.json('empty');
            }
        });
    });

// Update current user
router.route('/me')
    .put(function (req, res) {

        var userId = req.decoded.id;

        connect.query('SELECT * FROM users WHERE uid = ?', userId, function (err, users) {
            if (err) throw err;

            var user = users[0];

            if (!user) {
                res.status(404, 'User not found');
                return;
            }

            var newUser = Object.assign({}, user);

            if (req.body.phone && user.phone != req.body.phone) {
                newUser.phone = req.body.phone;
            }
            if (req.body.name && user.username != req.body.name) {
                newUser.username = req.body.name;
            }
            if (req.body.current_password) {
                if (user.password === req.body.current_password) {
                    if (req.body.new_password) {
                        newUser.password = req.body.new_password;
                    }
                    else {
                        res.json("new_password is empty");
                    }
                }
                else {
                    res.status(422, 'Unprocessable Entity');
                    res.json({'field': 'current_password', 'message': 'Wrong current password'});
                }
            }
            if (req.body.email && user.email != req.body.email) {
                connect.query('SELECT * FROM users WHERE email = ?', req.body.email, function (err, values) {
                    if (err) throw err;

                    var value = values[0];

                    if (value) {
                        res.json("user with this email already exist");
                    }
                    else {
                        newUser.email = req.body.email;

                        var sql = 'UPDATE users SET phone=?, username=?, email=?, password=? WHERE uid=?';
                        connect.query(sql, [newUser.phone, newUser.username, newUser.email, newUser.password, newUser.uid],
                            function (err, updateUser) {
                                if (err) throw err;

                                res.json(
                                    {
                                        'id': newUser.uid,
                                        'phone': newUser.phone,
                                        'name': newUser.username,
                                        'email': newUser.email
                                    });
                            });
                    }
                })
            }
            else {
                var sql = 'UPDATE users SET phone=?, username=?, email=?, password=? WHERE uid=?';
                connect.query(sql, [newUser.phone, newUser.username, newUser.email, newUser.password, newUser.uid],
                    function (err, updateUser) {
                        if (err) throw err;

                        res.json(
                            {
                                'id': newUser.uid,
                                'phone': newUser.phone,
                                'name': newUser.username,
                                'email': newUser.email
                            });
                    });
            }
        });
    });

// Get user by ID
router.route('/user/:id')
    .get(function (req, res) {

        var userId = req.params.id;

        var sql = 'SELECT * FROM users WHERE uid=?';
        connect.query(sql, userId, function (err, result) {
            if (err) throw err;

            var user = result[0];

            if (user) {
                res.status(200, 'OK');
                res.json(
                    {
                        'id': user.uid,
                        'phone': user.phone,
                        'name': user.username,
                        'email': user.email
                    });
            }
            else {
                res.status(404, 'Not found');
                res.json('empty');
            }
        })
    });

// Search users
router.route('/user?')
    .get(function (req, res) {

        var searchQuery = [];
        var sql = '';

        if (req.query.name && req.query.email) {
            searchQuery = [req.query.name, req.query.email];
            sql = 'SELECT uid, phone, username, email FROM users WHERE username=? OR email=?';
        }
        else if (!req.query.name && req.query.email) {
            searchQuery = [req.query.email];
            sql = 'SELECT uid, phone, username, email FROM users WHERE email=?';
        }
        else if (req.query.name && !req.query.email) {
            searchQuery = [req.query.name];
            sql = 'SELECT uid, phone, username, email FROM users WHERE username=?';
        }
        else {
            res.json('params is not found');
            return;
        }

        connect.query(sql, searchQuery, function (err, users) {
            if (err) throw err;

            if (users.length) {
                res.status(200, 'OK');
                res.json(users);
            }
            else {
                res.status(404, "User not found");
                res.json('Not found any user');
            }
        });
    });

//endregion

//region Items API
// Create item
router.route('/item')
    .post(function (req, res) {

        var userId = req.decoded.id;

        var sql = 'SELECT uid, phone, username, email FROM users WHERE uid=?';
        connect.query(sql, userId, function (err, users) {
            if (err) throw err;

            var user = users[0];

            var item = {
                created_at: (req.body.created_at == '') ? new Date() : req.body.created_at,
                title: req.body.title,
                price: req.body.price,
                product_img: req.body.img,
                uid: user.uid
            };

            if (user) {
                var sql = 'INSERT INTO items SET ?';
                if (item.title && item.price) {
                    connect.query(sql, item, function (err, result) {
                        if (err) throw err;

                        if (err) {
                            res.json(500, err);
                        }
                        else {
                            res.status(200, 'OK');
                            res.json({
                                'id': result.insertId,
                                'created_at': item.created_at,
                                'title': item.title,
                                'price': item.price,
                                'image': item.image,
                                'user_id': item.uid,
                                user: {
                                    'id': user.uid,
                                    'phone': user.phone,
                                    'name': user.username,
                                    'email': user.email
                                }
                            });
                        }

                    });
                }
                else {
                    res.status(422, 'Unprocessable Entity');
                    res.json({'field': 'title/price', 'message': 'Title and price is required'});
                }
            }
            else {
                res.status(401, 'Unauthorized');
            }
        });
    });

// Delete item by ID
router.route('/item/:id')
    .delete(function (req, res) {
        var userId = req.decoded.id;
        var itemId = req.params.id;

        connect.query('SELECT uid FROM items WHERE iid=?', itemId, function (err, result) {
            if (err) {
                throw err;
            }

            var item = result[0];

            if (item) {
                if (item.uid == userId) {
                    connect.query('DELETE FROM items WHERE iid=?', itemId, function (err, result) {
                        if (err) {
                            throw err;
                        }
                        else {
                            res.status(200, 'OK');
                            res.json('item is delete');
                        }
                    })
                }
                else {
                    res.status(403, "Forbidden");
                    res.end();
                }
            }
            else {
                res.status(404, "Not found");
                res.end();
            }
        });
    });

// Get item by ID
router.route('/item/:id')
    .get(function (req, res) {
        var itemId = req.params.id;

        var sql = 'SELECT items.*, users.uid, users.phone, users.username, users.email ' +
                    'FROM items, users WHERE items.iid=? AND items.uid=users.uid';
        connect.query(sql, itemId, function (err, result) {
            if (err) throw err;

            var item = result[0];

            if (item) {
                res.json({
                    'id': item.iid,
                    'created_at': item.created_at,
                    'title': item.title,
                    'price': item.price,
                    'image': item.product_img,
                    'uid': item.uid,
                    'user': {
                        'id': item.uid,
                        'phone': item.phone,
                        'name': item.username,
                        'email': item.email
                    }
                });
            }
            else {
                res.status(404, 'Not found');
            }
        });
    });

//endregion

app.use('/api', router);

app.listen(port, function () {
    console.log('Express server listening on port ' + port);
});