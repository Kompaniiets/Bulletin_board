--
-- Database: 'bulletin_board_db'
--
CREATE DATABASE IF NOT EXISTS bulletin_board_db;

-- --------------------------------------------------------

--
-- Table structure for table 'users'
--
CREATE TABLE IF NOT EXISTS 'users'
(
'uid' int(11) AUTO_INCREMENT PRIMARY KEY,
'username' varchar(255) NOT NULL UNIQUE KEY,
'password' varchar(255) NOT NULL,
'email' varchar(255) NOT NULL UNIQUE KEY,
'phone' varchar(15) UNIQUE KEY,
)
--
-- Table structure for table 'products'
--
CREATE TABLE IF NOT EXISTS 'products'
(
'pid' int(11) AUTO_INCREMENT PRIMARY KEY,
'created_at' datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
'title' varchar(100) NOT NULL,
'price' int(11) NOT NULL,
'product_img' varchar(100),
 )
 --
 -- Table structure for table 'sales'
 --
 CREATE TABLE IF NOT EXISTS 'sales'
 (
 'sid' int(11) AUTO_INCREMENT PRIMARY KEY,
 'pid' int(11),
 'uid' int(11),
 FOREIGN KEY(uid) REFERENCES users(uid),
 FOREIGN KEY(pid) REFERENCES products(pid)
 )