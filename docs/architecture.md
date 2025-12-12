# Hybrid Post-Quantum System Architecture

## Core Modules
1. **Quantum Engine:** Simulates BB84 protocol + interfaces with ANU QRNG.
2. **PQC Engine:** Emulates CRYSTALS-Kyber encapsulation.
3. **ML Engine:** Random Forest Fraud Detection.
4. **DB Engine:** Handles PostgreSQL connections and Pessimistic Locking.

## Transaction Flow
User -> App -> TransactionService -> (Parallel: QKD + PQC + ML) -> DB Lock -> Commit/Rollback.