import requests

def test_fabric_api():
    try:
        # Use the correct port
        url = 'http://localhost:13337/extwis'
        
        # Include a valid authorization token
        headers = {
            'Authorization': 'Bearer test',
            'Content-Type': 'application/json'
        }
        
        # Send a POST request with some input data
        data = {
            'input': 'Test input for wisdom extraction'
        }
        
        response = requests.post(url, json=data, headers=headers)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response Content: {response.text}")
        
        if response.status_code == 200:
            print("API is working correctly!")
        else:
            print("API returned an unexpected status code.")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while testing the API: {e}")

if __name__ == "__main__":
    test_fabric_api()