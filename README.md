# CRM

## Description

This project is a customer relationship management platform called ClientCore, designed to help small to medium businesses manage interactions with current and prospecting customers. It provides tools for tracking leads, managing contacts, organising and tracking sales pipelines, organising tasks and tracking progress on interactions.

## Installation

1. **Clone the repository:**
    
    Download all files from this GitHub Repository and place it in a folder named "CRM" in your desktop
    
2. **Manage File Structure & Directories**

    Ensure that the file structure is as follows at the bottom of this Readme file.

    

2. **Install dependencies:**
    Run the following command in the /CRM directory in your preferred terminal

    - pip install -r requirements.txt 
    

3. **Start the local server:**
    ```
    npm start
    ```

4. Open your browser and navigate to `http://localhost:3000`.

## Usage

- **Dashboard:** View an overview of your sales pipeline and recent activity.
- **Contacts:** Add, edit, or remove customer contact information.
- **Leads:** Track potential customers and their progress through the individual customer profiles which include interactions.

## License

This project is licensed under the [GNU GENERAL PUBLIC LICENSE](LICENSE).

## Directory Structure

```
CRM/
├── public/             # Static assets
├── src/
│   ├── components/     # React components
│   ├── pages/          # Application pages
│   ├── services/       # API and business logic
│   └── App.js          # Main app entry point
├── package.json        # Project metadata and dependencies
├── README.md           # Project documentation
└── LICENSE             # License information
```