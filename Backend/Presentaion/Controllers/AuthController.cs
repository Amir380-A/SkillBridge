using Backend.Models;
using Backend.Context;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using System.Linq;
using Backend.DTO;
using AutoMapper;
using Backend.Repository;
using Backend.Shared.Utils;
using System;

namespace Backend.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IUserRepository _userRepository;
        private readonly JwtHelper _jwtHelper;
        private readonly IMapper _mapper;
        private readonly EmailService _emailService;

        public AuthController(IUserRepository userRepository, JwtHelper jwtHelper, IMapper mapper, EmailService emailService)
        {
            _userRepository = userRepository;
            _jwtHelper = jwtHelper;
            _mapper = mapper;
            _emailService = emailService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto)
        {
            var existingUser = await _userRepository.GetUserByEmailAsync(dto.Email);
            if (existingUser != null)
                return BadRequest("Email already exists.");

            if (dto.Role != "Client" && dto.Role != "Freelancer")
                return BadRequest("Role should be 'Client' or 'Freelancer'.");

            var user = _mapper.Map<User>(dto);
            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password);

            // Generate a verification token
            var verificationToken = Guid.NewGuid().ToString();
            user.VerificationToken = verificationToken;
            user.IsEmailVerified = false;

            await _userRepository.AddUserAsync(user);
            await _userRepository.SaveAsync();

            // Send verification email
            await _emailService.SendVerificationEmailAsync(user.Email, user.Username, verificationToken);

            return Ok(new { userId = user.Id, message = "Registration successful! Please check your email to verify your account." });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto)
        {
            var user = await _userRepository.GetUserByEmailAsync(dto.Email);
            if (user == null || !BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
                return Unauthorized("Invalid username or password.");

            if (!user.IsEmailVerified)
                return Unauthorized("Please verify your email before logging in.");

            var token = _jwtHelper.GenerateToken(user);
            return Ok(new { token, userId = user.Id });
        }

        [HttpGet("verify-email")]
        public async Task<IActionResult> VerifyEmail(string token)
        {
            var user = await _userRepository.GetUserByVerificationTokenAsync(token);
            if (user == null)
                return BadRequest("Invalid or expired verification token.");

            user.IsEmailVerified = true;
            user.VerificationToken = null; 
            await _userRepository.SaveAsync();

            return Ok("Email verification successful! You can now log in.");
        }
    }
}
