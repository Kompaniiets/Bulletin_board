var express = require('express');
var app = express();
var bodyParser = require('body-parser');

var jwt = require('jsonwebtoken');
var config = require('./config');
var SECRET = 'someSecret';

var connect = require('./dbconnection');
var port = process.env.PORT || 8080;
app.set('secret', SECRET);

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));

// an instance of the router for api routes
var router = express.Router();

// Login user
router.route('/login')
    .post(function (req, res) {

        var email = req.body.email;
        var password = req.body.passw;

        connect.query('SELECT * FROM users WHERE email=?', email, function (err, user) {
            if (err) throw err;

            if (!user) {
                res.json({Body: {success: false, message: 'Authentication failed. User not found.'}});
            }
            else if (user) {
                if (user[0].password !== password) {
                    res.status(422, "Unprocessable Entity");
                    res.json({Body: {field: "password", message: "Wrong email or password"}});
                }
                else {
                    var token = jwt.sign({id: user[0].uid}, app.get('secret'), {
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

        connect.query('SELECT * FROM users WHERE email=?', email, function (err, user) {
            if (err) throw err;

            if (user[0]) {
                res.json({Body: {success: false, message: 'User already exist'}});
            }
            else if (user[0] == undefined) {
                //var sql = 'INSERT INTO users (username, email, password, phone) VALUES ?';
                var value = {username: name, email: email, password: password, phone: phone};
                console.log('inside');
                connect.query('INSERT INTO users SET ?', value, function (err, result) {

                    if (err) throw err;

                    console.log(result);

                    var token = jwt.sign({data: result}, app.get('secret'), {
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
    var token = req.body.token || req.query.token || req.headers['x-access-token'];

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

        connect.query('SELECT * FROM users WHERE uid = ?', userId, function (err, user) {
            if (err) throw err;

            else if (user) {
                res.status(200, 'OK')
                res.json(
                    {
                        'id': user[0].uid,
                        'phone': user[0].phone,
                        'name': user[0].username,
                        'email': user[0].email
                    });
            }
            else {
                res.status(401, 'Unauthorized');
                res.json('empty');
            }
        });
    });

app.use('/api', router);

app.listen(port, function () {
    console.log('Express server listening on port ' + port);
});