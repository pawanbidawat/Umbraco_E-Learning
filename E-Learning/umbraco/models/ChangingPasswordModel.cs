namespace Umbraco.Cms.Web.Website.Models
{
    public class ChangingPasswordModel
    {
        public string? OldPassword { get; set; }
        public string? NewPassword { get; set; }
        public string? ConfirmPassword { get; set; }
    }
}
