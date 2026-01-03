import mysql from 'mysql2/promise';

const initDatabase = async () => {
  let connection;
  
  try {
    connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT || 3306,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      multipleStatements: true
    });

    console.log('📦 Checking database tables...');

    // Create users table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        firstName VARCHAR(100) NOT NULL,
        lastName VARCHAR(100) NOT NULL,
        profileImage VARCHAR(500),
        email VARCHAR(255) NOT NULL UNIQUE,
        googleId VARCHAR(255) UNIQUE,
        password VARCHAR(255) NOT NULL,
        phone VARCHAR(20),
        address VARCHAR(255),
        city VARCHAR(100),
        state VARCHAR(100),
        zipCode VARCHAR(20),
        country VARCHAR(100),
        role ENUM('customer','admin') DEFAULT 'customer',
        isActive TINYINT(1) DEFAULT 1,
        isEmailVerified TINYINT(1) DEFAULT 0,
        emailVerificationToken VARCHAR(255),
        emailVerificationExpires DATETIME,
        emailVerifiedAt DATETIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_role (role),
        INDEX idx_isActive (isActive),
        INDEX idx_emailVerificationToken (emailVerificationToken)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // Create product table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS product (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        img VARCHAR(500) NOT NULL,
        rating DECIMAL(2,1) DEFAULT 0,
        price DECIMAL(10,2) NOT NULL,
        originalPrice DECIMAL(10,2),
        color VARCHAR(100),
        category VARCHAR(100) NOT NULL,
        sizes JSON,
        printType VARCHAR(100),
        material VARCHAR(100),
        reviews INT DEFAULT 0,
        isCustomizable BOOLEAN DEFAULT false,
        colors JSON,
        tag VARCHAR(100),
        fabricType VARCHAR(100),
        productionTime INT DEFAULT 1,
        featured BOOLEAN DEFAULT false,
        basePrice DECIMAL(10,2),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // Create orders table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        userId INT NOT NULL,
        orderNumber VARCHAR(100) UNIQUE NOT NULL,
        items JSON NOT NULL,
        totalAmount DECIMAL(10,2) NOT NULL,
        shippingAddress JSON,
        billingAddress JSON,
        paymentMethod VARCHAR(50) DEFAULT 'pending',
        paymentStatus ENUM('pending', 'paid', 'failed', 'refunded') DEFAULT 'pending',
        orderStatus ENUM('pending', 'processing', 'shipped', 'delivered', 'cancelled') DEFAULT 'pending',
        shippingCost DECIMAL(10,2) DEFAULT 0,
        tax DECIMAL(10,2) DEFAULT 0,
        discount DECIMAL(10,2) DEFAULT 0,
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    // Create settings table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        settingKey VARCHAR(255) NOT NULL UNIQUE,
        settingValue TEXT,
        settingType ENUM('string', 'number', 'boolean', 'json') DEFAULT 'string',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_key (settingKey)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);

    console.log('✅ Database tables initialized successfully');
    
  } catch (error) {
    console.error('❌ Error initializing database:', error);
    throw error;
  } finally {
    if (connection) {
      await connection.end();
    }
  }
};

export default initDatabase;