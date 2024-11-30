# add this to terminal=  streamlit run code_1.py 

import streamlit as st
import hashlib
import requests
import pandas as pd

# Function to securely hash passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Initialize session state variables for login status, username, and user data
if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
if 'username' not in st.session_state:
    st.session_state['username'] = None
if 'user_data' not in st.session_state:
    st.session_state['user_data'] = {}  # Use session state for user data    

# Function to handle user registration
def register():
    st.subheader("Register")
    username = st.text_input("Username", key="register_username")
    email = st.text_input("Email", key="register_email")
    password = st.text_input("Password", type="password", key="register_password")
    confirm_password = st.text_input("Confirm Password", type="password", key="register_confirm_password")

    if st.button("Register", key="register_button"):
        # Check if all fields are filled and passwords match
        if not username or not email or not password:
            st.warning("Please fill in all the fields.")
        elif username in st.session_state['user_data']:
            st.warning("Username already exists!")
        elif password != confirm_password:
            st.warning("Passwords do not match!")
        else:
            # Save the new user's details in session state
            st.session_state['user_data'][username] = {
                "email": email,
                "password": hash_password(password),
            }
            st.success("Registration successful! You can now log in.")

# Function to handle user login
def login():
    st.subheader("Login")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")

    if st.button("Login", key="login_button"):
        hashed_password = hash_password(password)
        # Check if the username and hashed password match the stored data
        if username in st.session_state['user_data'] and st.session_state['user_data'][username]["password"] == hashed_password:
            st.session_state['logged_in'] = True
            st.session_state['username'] = username
            st.success(f"Welcome, {username}")
        else:
            st.error("Invalid username or password")

# Function to handle user logout
def logout():
    st.session_state['logged_in'] = False
    st.session_state['username'] = None
    st.info("You have logged out.")

# Function to display user details
def user_details():
    username = st.session_state['username']
    if username and username in st.session_state['user_data']:
        st.subheader("User Details")
        st.write(f"*Username:* {username}")
        st.write(f"*Email:* {st.session_state['user_data'][username]['email']}")
        
        
 # registration and login apge completed till this , now next is connect database to it.       
 # MY api KEY FROM Alpha Vantage - U8GOJNKCH3NC1MP7   or  QPGED4EVATZ15EV   

# Function to fetch and display market data from Alpha Vantage
def fetch_market_data():
    st.subheader("Market Data")

    # Step 1: Set up your API key and the base URL
    api_key = "U8GOJNKCH3NC1MP7"  # with my Alpha Vantage API key
    base_url = "https://www.alphavantage.co/query"

    # Step 2: Define the parameters for the API request
    symbol = st.text_input("Enter Stock Symbol (e.g., AAPL)", value="AAPL")
    params = {
        "function": "TIME_SERIES_DAILY",
        "symbol": symbol,
        "outputsize": "compact",
        "apikey": api_key
    }

    if st.button("Fetch Data"):
        response = requests.get(base_url, params=params)
        data = response.json()
        
        # Step 4: Extract the time series data
        time_series = data.get("Time Series (Daily)", {})
        
        if not time_series:
            st.error("Failed to fetch data. Check your API key or symbol.")
            return
        
        # Step 5: Convert the data into a DataFrame
        df = pd.DataFrame.from_dict(time_series, orient="index")
        df = df.rename(columns={
            "1. open": "Open",
            "2. high": "High",
            "3. low": "Low",
            "4. close": "Close",
            "5. volume": "Volume"
        })
        df.index = pd.to_datetime(df.index)  # Convert the index to DateTime
        df = df.sort_index()  # Sort the DataFrame by date

        # Step 6: Display the data
        st.write("### Daily Stock Prices")     #AAPL,MSFT,GOOGL,AMZN,TSLA,NFLX,IBM,ORCL,INTC
        st.dataframe(df.head(20))  # Show the first 20 rows of the DataFrame

        # Plot the closing prices
        st.line_chart(df["Close"])
        st.bar_chart(df["Close"])
        st.scatter_chart(df["Close"])
        
        #st.altair_chart(df["Close"])
        #st.plotly_chart(df["Close"])
        


# Main function to handle the app's logic
def main():
    st.title("User Authentication and  Market Data analysis")

    # Navigation logic based on whether the user is logged in or not
    if not st.session_state['logged_in']:
        # Show the registration or login option in the sidebar
        st.sidebar.title("Menu")
        option = st.sidebar.radio("Choose an option:", ("Register", "Login"))

        if option == "Register":
            register()
        elif option == "Login":
            login()
    else:
        # Show the user details and logout option if logged in
        st.success(f"Logged in as {st.session_state['username']}")
        user_details()
        fetch_market_data()
        if st.button("Logout", key="logout_button"):
            logout()

if __name__ == "__main__":
    main()
