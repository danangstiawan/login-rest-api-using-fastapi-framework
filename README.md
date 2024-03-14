---
Project: TECHNICAL TEST ISMAYA LEGIT GROUP
Developer: Danang Stiawan
---

# Dummy User Login

"username": "ismayalegit",
"password": "password2024"

# 💁‍♀️ How to use

Run Local:
uvicorn main:app --reload

Create New Password
Run : generate_new_pass.py

Login (get token)
Endpoint API : /login
Body (json):
{
"username": "ismayalegit",
"password": "password2024"
}

Get Weather
Endpoint API : /weather/{city} Example: /weather/Jakarta
Header: Key: Authorization , Value : Bearer token (Example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJpc21heWFsZWdpdCIsInVzZXJuYW1lIjoiaXNtYXlhbGVnaXQiLCJlbWFpbCI6ImV4YW1wbGVAbWFpbC5jb20iLCJ0aW1lc3RhbXAiOjE3MTAzMTY1OTEuNzUxOTA5fQ.q0Ih5GjxaG9yTxVREcRlxSL8mTW9onN9xOShuwsH3f0)
