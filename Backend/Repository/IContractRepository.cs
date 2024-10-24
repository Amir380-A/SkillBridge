﻿using Backend.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Backend.Repository
{
    public interface IContractRepository
    {
        Task<List<Contract>> GetAllAsync();
        Task<Contract> GetByIdAsync(int id);
        Task AddAsync(Contract contract);
        Task UpdateAsync(Contract contract);
        Task DeleteAsync(Contract contract);
        Task<bool> SaveChangesAsync();
        Task<List<Contract>> GetByServiceIdAsync(int serviceId); // New method
        Task<List<Contract>> GetByUserIdAsync(int userId); // New method
    }
}
