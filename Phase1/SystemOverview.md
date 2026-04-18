# System Overview

## Domain Model
![Domain Model](images/domain-model.png)

## Use Case Diagram
![Use Case Diagram](images/use-case-diagram.png)

## Functional Requirements

## Non-Functional Requirements

## Security Requirements

### General Requirements
- All endpoints must enforce authentication.
- All inputs must be validated and sanitized.
- All communication must use HTTPS.
- Passwords must be securely hashed.
- Rate limiting must be applied to sensitive endpoints, such as login.

### User Requirements
- As an anonymous user, I can securely register and log in.
- As an authenticated user, I can manage my vaults and credentials.
- As an authenticated user, I can manage my trusted devices.
- As an administrator, I can manage users and assign roles.
- As an administrator, I can monitor system activity securely.
- As an administrator, I can enforce access control policies.

## Architectural Design

### Logic view

#### Level 1:
![Logic View N1](./images/VL/Vl1.png)

#### Level 2:
![Logic View N2](./images/VL/Vl2.png)

#### Level 3:
![Logic View N3](./images/VL/Vl3.png)

### Implementation View

#### Level 1:
![Implementation View N1](./images/VI/VI1.png)

#### Level 2:
![Implementation View N2](./images/VI/VI2.png)

#### Level 3:
![Implementation View N3](./images/VI/VI3.png)

### Deployment View
![Deployment View](./images/VD/VD_current.png)

#### Future Deployment View
![Future Deployment View](./images/VD/VD_future.png)