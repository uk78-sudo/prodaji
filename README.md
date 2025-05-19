using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using PaymentEduSystem.AuthService.Domain.Entities;
using PaymentEduSystem.AuthService.Domain.Exceptions;
using PaymentEduSystem.AuthService.Domain.Interfaces;
using PaymentEduSystem.AuthService.Domain.Models;

namespace PaymentEduSystem.AuthService.Domain.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthService> _logger;
        private readonly IRefreshTokenRepository _refreshTokenRepository;

        public AuthService(
            UserManager<ApplicationUser> userManager,
            IConfiguration configuration,
            ILogger<AuthService> logger,
            IRefreshTokenRepository refreshTokenRepository)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _refreshTokenRepository = refreshTokenRepository ?? throw new ArgumentNullException(nameof(refreshTokenRepository));
        }

        public async Task<AuthResponseDto> LoginAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByNameAsync(loginDto.Username);
            if (user == null)
            {
                _logger.LogWarning("User with username {Username} not found", loginDto.Username);
                throw new AuthenticationException("Invalid username or password");
            }

            var result = await _userManager.CheckPasswordAsync(user, loginDto.Password);
            if (!result)
            {
                _logger.LogWarning("Invalid password for user {Username}", loginDto.Username);
                throw new AuthenticationException("Invalid username or password");
            }

            var userRoles = await _userManager.GetRolesAsync(user);
            
            var accessToken = GenerateAccessToken(user, userRoles);
            var refreshToken = GenerateRefreshToken();
            
            var refreshTokenEntity = new RefreshToken
            {
                Token = refreshToken,
                UserId = user.Id,
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = loginDto.IpAddress ?? "Unknown"
            };
            
            await _refreshTokenRepository.AddAsync(refreshTokenEntity);
            
            return new AuthResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
                ExpiresIn = int.Parse(_configuration["JWT:ExpirationMinutes"] ?? "60") * 60,
                TokenType = "Bearer",
                UserId = user.Id,
                Username = user.UserName,
                Roles = userRoles.ToList()
            };
        }

        public async Task<AuthResponseDto> RefreshTokenAsync(RefreshTokenDto refreshTokenDto)
        {
            var refreshToken = await _refreshTokenRepository.GetByTokenAsync(refreshTokenDto.RefreshToken);
            if (refreshToken == null)
            {
                _logger.LogWarning("Refresh token not found: {RefreshToken}", refreshTokenDto.RefreshToken);
                throw new AuthenticationException("Invalid refresh token");
            }
            
            if (refreshToken.IsRevoked)
            {
                _logger.LogWarning("Refresh token is revoked: {RefreshToken}", refreshTokenDto.RefreshToken);
                throw new AuthenticationException("Refresh token has been revoked");
            }
            
            if (refreshToken.Expires < DateTime.UtcNow)
            {
                _logger.LogWarning("Refresh token expired: {RefreshToken}", refreshTokenDto.RefreshToken);
                throw new AuthenticationException("Refresh token has expired");
            }
            
            var user = await _userManager.FindByIdAsync(refreshToken.UserId);
            if (user == null)
            {
                _logger.LogWarning("User not found for refresh token: {RefreshToken}", refreshTokenDto.RefreshToken);
                throw new AuthenticationException("User not found");
            }
            
            var userRoles = await _userManager.GetRolesAsync(user);
            
            var accessToken = GenerateAccessToken(user, userRoles);
            var newRefreshToken = GenerateRefreshToken();
            
            refreshToken.Revoked = DateTime.UtcNow;
            refreshToken.RevokedByIp = refreshTokenDto.IpAddress ?? "Unknown";
            refreshToken.ReplacedByToken = newRefreshToken;
            await _refreshTokenRepository.UpdateAsync(refreshToken);
            
            var refreshTokenEntity = new RefreshToken
            {
                Token = newRefreshToken,
                UserId = user.Id,
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = refreshTokenDto.IpAddress ?? "Unknown"
            };
            
            await _refreshTokenRepository.AddAsync(refreshTokenEntity);
            
            return new AuthResponseDto
            {
                AccessToken = accessToken,
                RefreshToken = newRefreshToken,
                ExpiresIn = int.Parse(_configuration["JWT:ExpirationMinutes"] ?? "60") * 60,
                TokenType = "Bearer",
                UserId = user.Id,
                Username = user.UserName,
                Roles = userRoles.ToList()
            };
        }

        public async Task LogoutAsync(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
            {
                _logger.LogWarning("User with username {Username} not found during logout", username);
                return;
            }
            
            var activeRefreshTokens = await _refreshTokenRepository.GetActiveByUserIdAsync(user.Id);
            foreach (var token in activeRefreshTokens)
            {
                token.Revoked = DateTime.UtcNow;
                token.RevokedByIp = "User logout";
                await _refreshTokenRepository.UpdateAsync(token);
            }
        }

        public async Task<UserDto> GetUserByUsernameAsync(string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            if (user == null)
            {
                _logger.LogWarning("User with username {Username} not found", username);
                throw new NotFoundException($"User with username {username} not found");
            }
            
            var roles = await _userManager.GetRolesAsync(user);
            
            return new UserDto
            {
                Id = user.Id,
                Username = user.UserName,
                Email = user.Email,
                FirstName = user.FirstName,
                LastName = user.LastName,
                MiddleName = user.MiddleName,
                PhoneNumber = user.PhoneNumber,
                Roles = roles.ToList()
            };
        }

        public async Task<IEnumerable<UserDto>> GetAllUsersAsync()
        {
            var users = _userManager.Users.ToList();
            var userDtos = new List<UserDto>();
            
            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                
                userDtos.Add(new UserDto
                {
                    Id = user.Id,
                    Username = user.UserName,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    MiddleName = user.MiddleName,
                    PhoneNumber = user.PhoneNumber,
                    Roles = roles.ToList()
                });
            }
            
            return userDtos;
        }

        public async Task<UserDto> CreateUserAsync(CreateUserDto createUserDto)
        {
            var existingUser = await _userManager.FindByNameAsync(createUserDto.Username);
            if (existingUser != null)
            {
                _logger.LogWarning("User with username {Username} already exists", createUserDto.Username);
                throw new ValidationException($"User with username {createUserDto.Username} already exists");
            }
            
            if (await _userManager.FindByEmailAsync(createUserDto.Email) != null)
            {
                _logger.LogWarning("User with email {Email} already exists", createUserDto.Email);
                throw new ValidationException($"User with email {createUserDto.Email} already exists");
            }
            
            var user = new ApplicationUser
            {
                UserName = createUserDto.Username,
                Email = createUserDto.Email,
                FirstName = createUserDto.FirstName,
                LastName = createUserDto.LastName,
                MiddleName = createUserDto.MiddleName,
                PhoneNumber = createUserDto.PhoneNumber,
                EmailConfirmed = true
            };
            
            var result = await _userManager.CreateAsync(user, createUserDto.Password);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogWarning("Failed to create user {Username}: {Errors}", createUserDto.Username, errors);
                throw new ValidationException($"Failed to create user: {errors}");
            }
            
            if (createUserDto.Roles != null && createUserDto.Roles.Any())
            {
                result = await _userManager.AddToRolesAsync(user, createUserDto.Roles);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogWarning("Failed to add roles to user {Username}: {Errors}", createUserDto.Username, errors);
                    // Still continue as the user is created
                }
            }
            
            return await GetUserByUsernameAsync(user.UserName);
        }

        public async Task<UserDto> UpdateUserAsync(string id, UpdateUserDto updateUserDto)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                _logger.LogWarning("User with ID {UserId} not found", id);
                throw new NotFoundException($"User with ID {id} not found");
            }
            
            // Update user properties
            user.Email = updateUserDto.Email ?? user.Email;
            user.PhoneNumber = updateUserDto.PhoneNumber ?? user.PhoneNumber;
            user.FirstName = updateUserDto.FirstName ?? user.FirstName;
            user.LastName = updateUserDto.LastName ?? user.LastName;
            user.MiddleName = updateUserDto.MiddleName ?? user.MiddleName;
            
            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogWarning("Failed to update user {Username}: {Errors}", user.UserName, errors);
                throw new ValidationException($"Failed to update user: {errors}");
            }
            
            // Update password if provided
            if (!string.IsNullOrEmpty(updateUserDto.Password))
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                result = await _userManager.ResetPasswordAsync(user, token, updateUserDto.Password);
                
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogWarning("Failed to update password for user {Username}: {Errors}", user.UserName, errors);
                    throw new ValidationException($"Failed to update password: {errors}");
                }
            }
            
            // Update roles if provided
            if (updateUserDto.Roles != null && updateUserDto.Roles.Any())
            {
                var currentRoles = await _userManager.GetRolesAsync(user);
                
                // Remove all current roles
                if (currentRoles.Any())
                {
                    result = await _userManager.RemoveFromRolesAsync(user, currentRoles);
                    if (!result.Succeeded)
                    {
                        var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                        _logger.LogWarning("Failed to remove roles from user {Username}: {Errors}", user.UserName, errors);
                        throw new ValidationException($"Failed to update roles: {errors}");
                    }
                }
                
                // Add new roles
                result = await _userManager.AddToRolesAsync(user, updateUserDto.Roles);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogWarning("Failed to add roles to user {Username}: {Errors}", user.UserName, errors);
                    throw new ValidationException($"Failed to update roles: {errors}");
                }
            }
            
            return await GetUserByUsernameAsync(user.UserName);
        }

        public async Task DeleteUserAsync(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                _logger.LogWarning("User with ID {UserId} not found", id);
                throw new NotFoundException($"User with ID {id} not found");
            }
            
            var result = await _userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                _logger.LogWarning("Failed to delete user {Username}: {Errors}", user.UserName, errors);
                throw new ValidationException($"Failed to delete user: {errors}");
            }
            
            // Remove all refresh tokens for the user
            var refreshTokens = await _refreshTokenRepository.GetAllByUserIdAsync(id);
            foreach (var token in refreshTokens)
            {
                await _refreshTokenRepository.DeleteAsync(token.Id);
            }
        }

        private string GenerateAccessToken(ApplicationUser user, IEnumerable<string> roles)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim("first_name", user.FirstName ?? string.Empty),
                new Claim("last_name", user.LastName ?? string.Empty)
            };
            
            // Add roles to claims
            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
            
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expirationMinutes = int.Parse(_configuration["JWT:ExpirationMinutes"] ?? "60");
            
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
                signingCredentials: credentials
            );
            
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string GenerateRefreshToken()
        {
            return Guid.NewGuid().ToString();
        }
    }
}
