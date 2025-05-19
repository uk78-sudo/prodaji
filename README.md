# Repository Structure - PaymentEduSystem

## Project Overview
This repository contains the code for the Payment Education System, a comprehensive solution for managing educational payment services at Moscow Witte University. The system consists of several microservices, a client application, and supporting infrastructure.

## Directory Structure

```
/PaymentEduSystem
├── .github
│   └── workflows
│       ├── ci-build.yml
│       └── cd-deploy.yml
├── docker
│   ├── docker-compose.yml
│   └── Dockerfile.*
├── k8s
│   ├── api-gateway
│   ├── auth-service
│   ├── contract-service
│   ├── payment-service
│   └── notification-service
├── src
│   ├── ApiGateway
│   │   ├── PaymentEduSystem.ApiGateway
│   │   └── PaymentEduSystem.ApiGateway.Tests
│   ├── Services
│   │   ├── AuthService
│   │   │   ├── PaymentEduSystem.AuthService.API
│   │   │   ├── PaymentEduSystem.AuthService.Domain
│   │   │   ├── PaymentEduSystem.AuthService.Infrastructure
│   │   │   └── PaymentEduSystem.AuthService.Tests
│   │   ├── ContractService
│   │   │   ├── PaymentEduSystem.ContractService.API
│   │   │   ├── PaymentEduSystem.ContractService.Domain
│   │   │   ├── PaymentEduSystem.ContractService.Infrastructure
│   │   │   └── PaymentEduSystem.ContractService.Tests
│   │   ├── PaymentService
│   │   │   ├── PaymentEduSystem.PaymentService.API
│   │   │   ├── PaymentEduSystem.PaymentService.Domain
│   │   │   ├── PaymentEduSystem.PaymentService.Infrastructure
│   │   │   └── PaymentEduSystem.PaymentService.Tests
│   │   ├── DiscountService
│   │   │   ├── PaymentEduSystem.DiscountService.API
│   │   │   ├── PaymentEduSystem.DiscountService.Domain
│   │   │   ├── PaymentEduSystem.DiscountService.Infrastructure
│   │   │   └── PaymentEduSystem.DiscountService.Tests
│   │   ├── NotificationService
│   │   │   ├── PaymentEduSystem.NotificationService.API
│   │   │   ├── PaymentEduSystem.NotificationService.Domain
│   │   │   ├── PaymentEduSystem.NotificationService.Infrastructure
│   │   │   └── PaymentEduSystem.NotificationService.Tests
│   │   └── ReportService
│   │       ├── PaymentEduSystem.ReportService.API
│   │       ├── PaymentEduSystem.ReportService.Domain
│   │       ├── PaymentEduSystem.ReportService.Infrastructure
│   │       └── PaymentEduSystem.ReportService.Tests
│   └── Web
│       ├── AdminPortal
│       │   ├── public
│       │   └── src
│       │       ├── components
│       │       ├── pages
│       │       ├── redux
│       │       └── services
│       └── StudentPortal
│           ├── public
│           └── src
│               ├── components
│               ├── pages
│               ├── redux
│               └── services
├── shared
│   ├── PaymentEduSystem.Common
│   ├── PaymentEduSystem.MessageBus
│   └── PaymentEduSystem.Security
├── tools
│   ├── Database
│   │   └── Scripts
│   └── DevOps
│       └── Scripts
├── .dockerignore
├── .gitignore
├── README.md
└── PaymentEduSystem.sln
```

## Key Components

### Microservices
1. **Auth Service** - Handles user authentication and authorization
2. **Contract Service** - Manages educational contracts
3. **Payment Service** - Processes payments and invoices
4. **Discount Service** - Handles discounts and special offers
5. **Notification Service** - Manages communication with users
6. **Report Service** - Generates reports and analytics

### Frontend Applications
1. **Admin Portal** - Web application for university staff
2. **Student Portal** - Web application for students

### Shared Libraries
1. **Common** - Shared utilities and models
2. **MessageBus** - Message broker client for inter-service communication
3. **Security** - Shared security components

## Getting Started

### Prerequisites
- .NET Core 6.0 SDK
- Node.js 16+
- Docker and Docker Compose
- SQL Server 2019+
- RabbitMQ

### Development Setup
1. Clone the repository
2. Run database setup scripts from `tools/Database/Scripts`
3. Start required services with Docker Compose
4. Run the backend services
5. Start the frontend applications

## CI/CD Pipeline
The repository includes GitHub Actions workflows for continuous integration and deployment:
- `ci-build.yml` - Builds and tests the application for every push and pull request
- `cd-deploy.yml` - Deploys the application to the test environment for changes to the main branch

## Contributors
- Student Developer Team, Moscow Witte University
