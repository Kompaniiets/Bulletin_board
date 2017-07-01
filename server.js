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

// login user
router.route('/login')
    .post(function (req, res) {

        connect.query('SELECT * FROM users WHERE email=?', [req.body.email],  function (err, user) {
            if(err) throw err;

            if(!user) {
                res.json({Body : {success: false, message: 'Authentication failed. User not found.'}});
            }
            else if(user){
                if(user[0].password !== req.body.passw){
                    res.status(422, "Unprocessable Entity");
                    res.json({Body : {field: "password", message: "Wrong email or password"}});
                }
                else {
                    //var token = jwt.sign({ foo: 'bar' }, 'secret');
                    var token = jwt.sign({ data: user }, app.get('secret'), {
                        expiresIn: '2h' // expires in 3 hours
                    });

                    res.status(200, "OK");
                    res.json({Body : {token: token}});
                }
            }
        });
    });

// route middleware to verify a token
router.use(function (req, res, next) {

    // check header or url parameters or post parameters for token
    var token = req.body.token || req.query.token || req.headers['x-access-token'];

    // decode token
    if(token){
        jwt.verify(token, app.get('secret'), function (err, decoded) {
            if(err) {
                res.json({ success: false, message: 'Failed to authenticate token.' });
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

router.get('/', function(req, res) {
    res.json({ message: 'hooray! welcome to our api!' });
});

app.use('/api', router);

app.listen(port, function () {
    console.log('Express server listening on port ' + port);
});