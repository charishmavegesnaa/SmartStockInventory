# 📦 SmartStockInventory

## 📖 About the Project

SmartStockInventory is a Flask-based inventory management system that helps manage products, monitor stock levels, and automate alerts.

The system integrates with **MongoDB** for data storage and includes advanced features like duplicate detection, price updates, and alert notifications.

It is designed to improve efficiency in inventory tracking and reduce manual errors.


## 🚀 Features

* 📊 Inventory management system using MongoDB
* 🔐 User authentication (JWT-based login system)
* ⚠️ Automated stock alerts system
* 📧 Email notifications using SMTP
* 🔁 Duplicate product detection and fixing
* 💰 Quick price update functionality
* 📁 CSV testing and data handling utilities
* 🔄 Robust database connection handling (retry + pooling)


## 🛠️ Technologies Used

* 🐍 Python
* 🌐 Flask
* 🍃 MongoDB (via PyMongo)
* 🔐 JWT Authentication
* 📧 SMTP (Email alerts)
* 🎨 HTML, CSS (Templates)
* 🔄 Flask-CORS


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


### 3️⃣ Install Dependencies

⚠️ If you don’t have `requirements.txt`, install manually:

```bash
pip install flask pymongo flask-cors pyjwt
```


### 4️⃣ Start MongoDB

Make sure MongoDB is running locally:

```bash
mongodb://localhost:27017/
```


### 5️⃣ Run Application

```bash
python app.py
```


### 6️⃣ Open Browser

```
http://127.0.0.1:5000/
```


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


## 📸 Screenshots

### Login Page

<img width="1873" height="897" alt="image" src="https://github.com/user-attachments/assets/57019a6d-e685-4ad1-b9c6-250437caa921" />


### Admin Dashboard

<img width="1896" height="895" alt="image" src="https://github.com/user-attachments/assets/2493c434-ba95-49d3-a510-008b915dabf8" />

### Products 

<img width="1902" height="897" alt="image" src="https://github.com/user-attachments/assets/b728dad8-77aa-4e30-8154-098d9e3098b1" />


### Inventory

<img width="1616" height="818" alt="image" src="https://github.com/user-attachments/assets/f5fd5574-0046-45b7-b11f-19327f2cfe67" />

### Sales & Transactions

<img width="1885" height="916" alt="image" src="https://github.com/user-attachments/assets/68c45f6b-41e0-4a6c-a7f8-9b8fb8c1d4b3" />

### Alerts System

<img width="1898" height="905" alt="image" src="https://github.com/user-attachments/assets/aa8f6655-6fc6-4bed-8ed8-0d5076b0a38d" />

### Reports

<img width="1895" height="906" alt="image" src="https://github.com/user-attachments/assets/926e32c5-a746-4438-952f-6852bb6d55cc" />

### Smart Assistant

<img width="1902" height="897" alt="image" src="https://github.com/user-attachments/assets/1385c3ef-f652-4cd1-8df3-22236646c174" />



## 📌 Future Improvements

* 📱 Responsive UI
* ☁️ Cloud MongoDB (Atlas) integration
* 📈 Analytics dashboard
* 🔐 Role-based access control

