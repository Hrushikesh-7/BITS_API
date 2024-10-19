import requests
import pytest
import re

# API URL and key
BASE_URL = "https://mzo5slmo45.execute-api.eu-west-2.amazonaws.com/v1/users"
API_KEY = "GombImxOhMCa8AqMmNM9KEFwaSHSFHty"

# Header with authorization key
HEADERS = {
    "Authorization": API_KEY,
    "Content-Type": "application/json"
}

@pytest.fixture
def create_user():
    payload = {
        "title": "Mr",
        "firstName": "Brit",
        "lastName": "Testing",
        "dateOfBirth": "2024-10-17",
        "email": "brittestingdata@email.com",
        "password": "testing",
        "rating": 4
    }
    response = requests.post(BASE_URL, json=payload, headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["data"]["status"] == "new"
    user_id = response.json()["data"]["userId"]
    return user_id  # Return the userId from the fixture


def test_post_user(create_user):
    assert create_user is not None
    print(create_user)


def test_get_user(create_user):
    # Use the userId from the fixture to get the user details
    get_url = f"{BASE_URL}/{create_user}"
    response = requests.get(get_url, headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["data"]["userId"] == create_user


def test_invalid_authentication(create_user):
    invalid_headers = {
        "Authorization": "",
        "Content-Type": "application/json"
    }
    get_url = f"{BASE_URL}/{create_user}"
    response = requests.get(get_url, headers=invalid_headers)
    # Assert that the response status code is 401 Unauthorized
    assert response.status_code == 401
    assert "Unauthorized" in response.json()["message"]


def test_create_user_with_accepted_titles():
    titles = ["Mr", "Mrs", "Miss", "Ms", "Mx", "dr"]
    accepted_titles = ["Mr", "Mrs", "Miss", "Ms", "Mx"]
    for title in titles:
        payload = {
            "title": title,
            "firstName": "title",
            "lastName": "testing",
            "dateOfBirth": "2024-10-17",
            "email": "titletesting@example.com",
            "password": "testing",
            "rating": 6
        }
        response = requests.post(BASE_URL, json=payload, headers=HEADERS)
        if title in accepted_titles:
            if response.status_code != 200:
                print(
                    f"Error: Expected 200 for title '{title}', but got {response.status_code} - {response.json()['errorMessage']}")
            else:
                print(f"Successfully created user with title '{title}': {response.json()['data']['title']}")
        else:
            if response.status_code != 400:
                print(f"Error: Expected 400 for title '{title}', but got {response.status_code}")
            else:
                print(f"Correctly received 400 for invalid title '{title}': {response.json()['errorMessage']}")


def test_firstname_character_count():
    firstname_char = ["t", "te", "test", "T"*257, 123]
    for firstname in firstname_char:
        payload = {
            "title": "Mr",
            "firstName": firstname,
            "lastName": "testing",
            "dateOfBirth": "2024-10-17",
            "email": "maxlength@example.com",
            "password": "testing",
            "rating": 4
        }
        response = requests.post(BASE_URL, json=payload, headers=HEADERS)
        if not isinstance(firstname, str):
            print(f"User creation failed because firstname is not a string: {firstname}")
            assert response.status_code == 400, f"Expected 400 for non-string firstname '{firstname}', but got {response.status_code}"
            assert "ERR_FNAME_INVALID" in response.json()["errorMessage"], f"Expected 'ERR_FNAME_INVALID' in errorMessage, but got {response.json()['errorMessage']}"

        elif len(firstname) < 2 or len(firstname) > 255:
            print(f"User creation failed due to length less than 2 characters or more than 255: {firstname}")
            assert response.status_code == 400, f"Expected 400 for firstname '{firstname}', but got {response.status_code}"
            assert "ERR_FNAME_INVALID" in response.json()["errorMessage"], f"Expected 'ERR_FNAME_INVALID' in errorMessage, but got {response.json()['errorMessage']}"
        else:
            print(f"User creation successful for firstname: {firstname}")
            assert response.status_code == 200, f"Expected 200 for valid firstname '{firstname}', but got {response.status_code}"
            assert response.json()[
                       "status"] == "Success", f"Expected 'Success' in status, but got {response.json()['status']}"


def test_lastname_character_count():
    lastname_char = ["t", "te", "test", 123, "T"*257]
    for lastname in lastname_char:
        payload = {
            "title": "Mr",
            "firstName": "brit",
            "lastName": lastname,
            "dateOfBirth": "2024-10-17",
            "email": "maxlength@example.com",
            "password": "testing",
            "rating": 4
        }
        response = requests.post(BASE_URL, json=payload, headers=HEADERS)
        if not isinstance(lastname, str):
            print(f"User creation failed because lastname is not a string: {lastname}")
            assert response.status_code == 400
            assert "Internal server error" in response.json()["errorMessage"]

        elif len(lastname) < 2 or len(lastname) > 255:
            print(f"User creation failed due to length less than 2 characters or more than 255: {lastname}")
            assert response.status_code == 400, f"Expected 400 for lastname '{lastname}', but got {response.status_code}"
            assert "Validation error - last name must be between 2 and 255 characters" in response.json()["errorMessage"], f"Expected 'ERR_FNAME_INVALID' in errorMessage, but got {response.json()['errorMessage']}"
        else:
            print(f"User creation successful for lastname: {lastname}")
            assert response.status_code == 200, f"Expected 200 for valid lastname '{lastname}', but got {response.status_code}"
            assert response.json()[
                       "status"] == "Success", f"Expected 'Success' in status, but got {response.json()['status']}"


def test_create_user_rating():
    rating = [1, 4, 10]
    for num in rating:
        payload = {
            "title": "Mr",
            "firstName": "rating",
            "lastName": "testing",
            "dateOfBirth": "2024-10-18",
            "email": "ratingtesting@example.com",
            "password": "testing",
            "rating": num
        }
        response = requests.post(BASE_URL, json=payload, headers=HEADERS)
        if response.status_code != 200:
            print(f"{response.status_code}\n{response.json()['errorMessage']}")
        else:
            if num > 4:
                print("rating:",num)
                print(f'status: {response.json()["data"]["status"]}')
                assert response.json()["data"]["status"] == "active"
            elif num != 0 and num < 5:
                print("rating:",num)
                print(f'status: {response.json()["data"]["status"]}')
                assert response.json()["data"]["status"] == "new"
            else:
                assert response.json()["data"]["status"] == "Rejected"


def test_dob_format():
    # Test cases: valid and invalid date formats
    dob_cases = [
        "2024-10-17",  # Valid YYYY-MM-DD
        "17-10-2024",  # Invalid DD-MM-YYYY
        "10-17-2024",  # Invalid MM-DD-YYYY
        "2024/10/17",  # Invalid YYYY/MM/DD
        "20241017",  # Invalid no separators
        None,  # Invalid None type
        12345678  # Invalid number type
    ]
    # regex pattern for valid YYYY-MM-DD format
    valid_date_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}$")

    for dob in dob_cases:
        payload = {
            "title": "Mr",
            "firstName": "Test",
            "lastName": "Testing",
            "dateOfBirth": dob,
            "email": "dobtesting@example.com",
            "password": "testing",
            "rating": 4
        }

        response = requests.post(BASE_URL, json=payload, headers=HEADERS)

        # Check if the DOB matches the valid format
        if isinstance(dob, str) and valid_date_pattern.match(dob):
            print(f"User creation successful for valid dateOfBirth: {dob}")
            assert response.status_code == 200, f"Expected 200 for valid dateOfBirth '{dob}', but got {response.status_code}"
            assert response.json()["status"] == "Success"
        else:
            print(f"User creation failed due to an invalid calendar date for dateOfBirth: {dob}")
            assert response.status_code == 400, f"Expected 400 for invalid calendar date '{dob}', but got {response.status_code}"


def test_email_required():
    payload = {
        "title": "Mr",
        "firstName": "brit",
        "lastName": "testing",
        "dateOfBirth": "2024-10-17",
        "password": "securepassword",
        "rating": 5
    }
    response = requests.post(BASE_URL, json=payload, headers=HEADERS)
    assert response.status_code == 502
    assert "Internal server error" in response.json()["message"]


def test_password():
    payload = {
        "title": "Mr",
        "firstName": "brit",
        "lastName": "testing",
        "dateOfBirth": "2024-10-17",
        "email": "brittesting@example.com",
        "rating": 5
    }
    response = requests.post(BASE_URL, json=payload, headers=HEADERS)
    if response.status_code == 200:
        print("Required criteria for password is not implemented successfully")
    else:
        print("Acceptance criteria is implemented properly")


def test_email_invalid_format():
    example_emails = [
        "username@example.com",
        "user.name@domain.com",
        "user-name@domain.com",
    ]
    for email in example_emails:
        payload = {
            "title": "Mr",
            "firstName": "Brit",
            "lastName": "test",
            "dateOfBirth": "2024-10-17",
            "email": email,
            "password": "testing",
            "rating": 5
        }
        response = requests.post(BASE_URL, json=payload, headers=HEADERS)
        # Check for invalid characters before the '@' symbol
        if any(char in email[:email.index('@')] for char in ['.', '+', '-']):
            assert response.status_code == 400
            assert "Invalid email address format" in response.json()["errorMessage"]
        else:
            print(email)
            assert response.status_code == 200
            assert "userId" in response.json()["data"]


def test_email_uniqueness():
    # Payload for the first request
    payload = {
        "title": "Mr",
        "firstName": "Brit",
        "lastName": "Testing",
        "dateOfBirth": "2024-10-17",
        "email": "brittestingdata@email.com",
        "password": "testing",
        "rating": 4
    }

    # First request to create a user with a unique email
    response = requests.post(BASE_URL, json=payload, headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["status"] == "Success"
    user_id = response.json()["data"]["userId"]
    print(f"User created with ID: {user_id}")

    # Second request to create the same user again with the same email
    duplicate_response = requests.post(BASE_URL, json=payload, headers=HEADERS)
    duplicate_user_id = response.json()["data"]["userId"]
    print(duplicate_user_id)

    if duplicate_response.status_code == 400:
        print("unique email is required")
    else:
        print("able to create a user account with same email address that exists")


def test_user_rating_bugs():
    rating = [0, 5, 25]
    for num in rating:
        payload = {
            "title": "Mr",
            "firstName": "rating",
            "lastName": "testing",
            "dateOfBirth": "2024-10-18",
            "email": "ratingtesting@example.com",
            "password": "testing",
            "rating": num
        }
        response = requests.post(BASE_URL, json=payload, headers=HEADERS)
        if response.status_code != 200:
            print(f"{response.status_code}\n{response.json()['errorMessage']}")
        else:
            try:
                if num > 4:
                    print("rating:", num)
                    print(f'status: {response.json()["data"]["status"]}')
                    assert response.json()["data"]["status"] == "active"
                elif num != 0 and num < 5:
                    print("rating:", num)
                    print(f'status: {response.json()["data"]["status"]}')
                    assert response.json()["data"]["status"] == "new"
                else:
                    assert response.json()["data"]["status"] == "Rejected"
            except AssertionError as e:
                print(f"Assertion failed for rating {num}: {e}")

