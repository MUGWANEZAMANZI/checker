import random

# List of common first and last names
first_names = ["soc", "Emma", "Liam", "Olivia", "Noah", "Ava", "William", "Sophia", "James", "Isabella"]
last_names = ["Smith", "Johnson", "Brown", "Williams", "Jones", "Miller", "Davis", "Garcia", "Rodriguez", "Wilson"]

def generate_usernames(count=500):
    usernames = []
    for i in range(count):
        first = random.choice(first_names)
        last = random.choice(last_names)
        number = random.randint(10, 99)  # Add a number to make it more unique
        if (i%2==0):
                 username = f"{first}{last}{number}"
        else:
                username = f"{first}{last}"
        usernames.append(username)
    return usernames

# Save usernames to a file
output_file = "usernames.txt"
with open(output_file, "w") as file:
    for username in generate_usernames():
        file.write(username + "\n")

print(f"Usernames saved to {output_file}")
