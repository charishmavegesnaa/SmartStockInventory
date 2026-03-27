# 📦 SmartStockInventory

## 📖 About the Project

SmartStockInventory is a Flask-based inventory management system that helps manage products, monitor stock levels, and automate alerts.

The system integrates with **MongoDB** for data storage and includes advanced features like duplicate detection, price updates, and alert notifications.

It is designed to improve efficiency in inventory tracking and reduce manual errors.

---

## 🚀 Features

* 📊 Inventory management system using MongoDB
* 🔐 User authentication (JWT-based login system)
* ⚠️ Automated stock alerts system
* 📧 Email notifications using SMTP
* 🔁 Duplicate product detection and fixing
* 💰 Quick price update functionality
* 📁 CSV testing and data handling utilities
* 🔄 Robust database connection handling (retry + pooling)

---

## 🛠️ Technologies Used

* 🐍 Python
* 🌐 Flask
* 🍃 MongoDB (via PyMongo)
* 🔐 JWT Authentication
* 📧 SMTP (Email alerts)
* 🎨 HTML, CSS (Templates)
* 🔄 Flask-CORS

---

## ▶️ How to Run the Project

### 1️⃣ Clone Repository

```bash
git clone https://github.com/charishmavegesnaa/SmartStockInventory.git
cd SmartStockInventory
```

---

### 2️⃣ Create Virtual Environment

```bash
python -m venv venv
venv\Scripts\activate   # Windows
```

---

### 3️⃣ Install Dependencies

⚠️ If you don’t have `requirements.txt`, install manually:

```bash
pip install flask pymongo flask-cors pyjwt
```

---

### 4️⃣ Start MongoDB

Make sure MongoDB is running locally:

```bash
mongodb://localhost:27017/
```

---

### 5️⃣ Run Application

```bash
python app.py
```

---

### 6️⃣ Open Browser

```
http://127.0.0.1:5000/
```

---

## 📂 Project Structure

```
smartstock/
│── app.py                  # Main Flask app
│── alerts.py               # Alert system
│── quick_fix_price.py      # Price update logic
│── test_alert_fix.py       # Testing alerts
│── test_csv.py             # CSV testing
│── templates/              # HTML files
│── static/                 # CSS/JS files
│── *.md                    # Documentation files
```


## 📌 Future Improvements

* 📱 Responsive UI
* ☁️ Cloud MongoDB (Atlas) integration
* 📈 Analytics dashboard
* 🔐 Role-based access control
