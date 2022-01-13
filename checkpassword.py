import sys
import requests
import hashlib

'''
Parth Patel

The password checker implements the SHA1 hashing algorithm to get the hash of the password.
The requests library is used to get the API from pwnedpasswords website

The first five characters are used for the k-anonymity model for privacy protection, rather than use the whole password
as the query for the API

The text file pwd.txt is where the passwords are stored as input


'''

def get_password_from_file(file_path):
    lines = []
    try:
        with open(file_path) as my_file:
            for line in my_file:
                line = line.strip()
                if ' ' in line:
                    split_line = line.split(' ')
                    for password_str in split_line:
                        lines.append(password_str)
                else:
                    lines.append(line)
    except FileNotFoundError as err:
        print('File does not exist.')
    return lines

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # Check password if it exists in API response
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_five_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first_five_char)
    return get_password_leaks_count(response, tail)


def password_input(file):
    lines = get_password_from_file(file)
    for password in lines:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times...you should probably change your password.')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'done!'

def main():
    password_input('pwd.txt')

if __name__ == '__main__':
    sys.exit(main())
