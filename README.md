# CRM

## Description

This project is a customer relationship management platform called ClientCore, designed to help small to medium businesses manage interactions with current and prospecting customers. It provides tools for tracking leads, managing contacts, organising and tracking sales pipelines, organising tasks and tracking progress on interactions.

## Installation

1. **Clone the repository:**
    
    Download all files from this GitHub Repository and place it in a folder named "CRM" in your desktop
    
2. **Manage File Structure & Directories**

    Ensure that the file structure is as follows at the bottom of this Readme file.

    

2. **Install dependencies:**

    Navigate to the location of the CRM file
    
    Run the following command in the /CRM directory in your preferred terminal
    ```
    pip install -r requirements.txt 
    ```

3. **Start the local server:**
    ```
    python app.py
    ```

4. **Open website on browser**

    Open your browser and navigate to `http://localhost:5000`.

## Usage

- **Dashboard:** View an overview of your sales pipeline and recent customer activity in the home page as soon as you log in.
- **Contacts:** Add, edit, or remove customer contact information.
- **Lists** Create, edit or remove customer lists to organise groups of customers.
- **Tasks** Create tasks and track task progression and complete tasks on time, attach customers to tasks.
- **Leads:** Track potential customers and their progress through the individual customer profiles which include interactions.

## License

This project is licensed under the [GNU GENERAL PUBLIC LICENSE](LICENSE).

## Directory Structure

```
CRM/
├── app.py/             # Main application gateway and Flask backend
├── templates/              # Application HTML pages, all inside templates folder
│   ├── add_customer.html/     
│   ├── add_list.html/         
│   ├── add_task.html/       
│   └── customers.html/          
│   └── edit_customer.html/          
│   └── edit_interaction.html/          
│   └── edit_task.html/          
│   └── index.html/          
│   └── lists.html/          
│   └── login.html/          
│   └── register.html/          
│   └── tasks.html/          
│   └── view_customer.html/          
│   └── view_list.html/                    
├── requirements.txt        # Project and dependencies
├── README.md           # Project documentation
└── LICENSE             # License information
```