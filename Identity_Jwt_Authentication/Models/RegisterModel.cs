﻿namespace Identity_Jwt_Authentication.Models
{
    public class RegisterModel
    {
        public string UserName { get; set; }    
        public string Password { get; set; }
        public string Email { get; set; }   
        public string PhoneNumber { get; set; }
    }
}
