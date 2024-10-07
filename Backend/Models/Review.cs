﻿namespace Backend.Models
{
    public class Review
    {
        public int ReviewId  { get; set; }
        public int ServiceId { get; set; }
        public int BuyerId { get; set; }
        public int Rating { get; set; } 
        public string Comment { get; set; }
        

        
        public virtual Service Service { get; set; }
        public virtual User Buyer { get; set; }
    }

}
