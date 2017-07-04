var express = require('express');
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');
var formidable = require('formidable');
var fs = require('fs');

var app = express();

var config = require('./config');
var connect = require('./dbconnection');

var port = process.env.PORT || 8080;

app.set('secret', config.secret);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));

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

        var regex = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

        if (regex.test(email)) {

            if (password.length > 5 && password.length < 20) {
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
            }
            else {
                res.status(422, "Unprocessable Entity");
                res.json('Enter a valid valid password');
            }
        }
        else {
            res.status(422, "Unprocessable Entity");
            res.json('Enter a valid email address');
        }
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
                res.end();
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
                res.end();
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
                res.end();
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
                res.end();
            }
        });
    });

// Search items
router.route('/item')
    .get(function (req, res) {

        var searchQuery = [];
        var sql = '';
        var order_by = (req.query.order_by != 'price') ? 'items.created_at' : 'items.price';
        var order_type = (req.query.order_type != 'asc') ? ' DESC' : ' ASC';

        if (req.query.title && req.query.user_id) {
            searchQuery = [req.query.title, req.query.user_id];
            sql = 'SELECT items.*, users.uid, users.phone, users.username, users.email ' +
                'FROM items, users WHERE (items.title=? OR items.uid=?) AND users.uid=items.uid ORDER BY ' + order_by + order_type;
        }
        else if (!req.query.title && req.query.user_id) {
            searchQuery = [req.query.user_id];
            sql = 'SELECT items.*, users.uid, users.phone, users.username, users.email ' +
                'FROM items, users WHERE items.uid=? AND users.uid=items.uid ORDER BY ' + order_by + order_type;
        }
        else if (req.query.title && !req.query.user_id) {
            searchQuery = [req.query.title];
            sql = 'SELECT items.*, users.uid, users.phone, users.username, users.email ' +
                'FROM items, users WHERE items.title=? AND users.uid=items.uid ORDER BY ' + order_by + order_type;
        }
        else {
            sql = 'SELECT items.*, users.uid, users.phone, users.username, users.email ' +
                'FROM items, users WHERE users.uid=items.uid ORDER BY ' + order_by + order_type;
        }

        connect.query(sql, searchQuery, function (err, items) {
            if (err) throw err;

            var findItem = {};

            if (items) {
                for (var i = 0; i < items.length; i++) {
                    findItem[i] = {
                        'id': items[i].iid,
                        'created_at': items[i].created_at,
                        'title': items[i].title,
                        'price': items[i].price,
                        'image': items[i].image,
                        'user_id': items[i].uid,
                        user: {
                            'id': items[i].uid,
                            'phone': items[i].phone,
                            'name': items[i].username,
                            'email': items[i].email
                        }
                    };
                }
                res.json(findItem);
            }

            else {
                res.status(404, 'Not found');
                res.end();
            }
        });
    });

// Update item
router.route('/item/:id')
    .put(function (req, res) {

        var itemID = req.params.id;
        var regex = /^\d+(?:\.\d{0,2})$/;

        if (!req.body.title || req.body.title < 3) {
            res.status(422, 'Unprocessable Entity');
            res.json({"field": "title", "message": "Title should contain at least 3 characters"});
        }
        if (!req.body.price || !regex.test(req.body.price)) {
            res.status(422, 'Unprocessable Entity');
            res.json({"field": "price", "message": "Price is not valid"});
        }

        var sql = 'SELECT items.*, users.uid, users.phone, users.username, users.email ' +
            'FROM items, users WHERE items.iid=? AND users.uid=items.uid';
        connect.query(sql, itemID, function (err, result) {
            if (err) throw err;

            var item = result[0];
            var newItem = Object.assign({}, item);

            if (item) {
                var current_userId = req.decoded.id;

                if (item.uid == current_userId) {
                    if (item.title && item.title != req.body.title) {
                        newItem.title = req.body.title;
                    }
                    if (item.price && item.price != req.body.price) {
                        newItem.price = req.body.price;
                    }

                    var sql = 'UPDATE items SET title=?, price=? WHERE iid= ' + itemID;
                    connect.query(sql, [newItem.title, newItem.price], function (err, result) {

                        if (err) throw err;

                        else {
                            res.status(200, 'OK');
                            res.json({
                                'id': newItem.iid,
                                'created_at': newItem.created_at,
                                'title': newItem.title,
                                'price': newItem.price,
                                'product_img': newItem.product_img,
                                'user_id': newItem.uid,
                                 user: {
                                     'id': newItem.uid,
                                     'telephone': newItem.telephone,
                                     'name': newItem.username,
                                     'email': newItem.email
                                 }
                            });
                        }
                    });
                }
            }
            else {
                res.status(404, 'Not found');
                res.end();
            }
        });
    });

// Upload item image
router.route('/item/:id/image')
    .post(function (req, res) {

        var itemId = req.params.id;
        if (req.url == '/item/' + itemId + '/image' && req.method.toLowerCase() == 'post') {

            var form = new formidable.IncomingForm();
            //form.uploadDir = './public/img/upload_img';

            form.parse(req);

            form.on('fileBegin', function (name, file){
                file.path = __dirname + '/public/img/upload_img/' + file.name;
            });

            form.on('file', function (name, file){
                console.log('Uploaded ' + file.name);
            });
        }
    });

//endregion

app.use('/api', router);

app.listen(port, function () {
    console.log('Express server listening on port ' + port);
});