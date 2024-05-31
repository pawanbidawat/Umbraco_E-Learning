using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Net;
using System.Net.Mail;
using System.Web;
using Umbraco.Cms.Core.Cache;
using Umbraco.Cms.Core.Logging;
using Umbraco.Cms.Core.Models;
using Umbraco.Cms.Core.Models.ContentEditing;
using Umbraco.Cms.Core.Models.Membership;
using Umbraco.Cms.Core.Routing;
using Umbraco.Cms.Core.Scoping;
using Umbraco.Cms.Core.Security;
using Umbraco.Cms.Core.Services;
using Umbraco.Cms.Core.Web;
using Umbraco.Cms.Infrastructure.Persistence;
using Umbraco.Cms.Web.Common.Filters;
using Umbraco.Cms.Web.Common.Security;
using Umbraco.Cms.Web.Website.Controllers;
using Umbraco.Cms.Web.Website.Models;
using ChangingPasswordModel = Umbraco.Cms.Core.Models.ChangingPasswordModel;

namespace E_Learning.Controllers
{
    public class RegisterMemberController : SurfaceController
    {
        private readonly IMemberManager _memberManager;
        private readonly IMemberService _memberService;
        private readonly IMemberSignInManager _memberSignInManager;
        private readonly ICoreScopeProvider _coreScopeProvider;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public RegisterMemberController(
            IConfiguration configuration,
            IHttpContextAccessor httpContextAccessor,
            IMemberManager memberManager,
            IMemberService memberService,
            IMemberSignInManager memberSignInManager,
            ICoreScopeProvider coreScopeProvider,
            IUmbracoContextAccessor umbracoContextAccessor,
            IUmbracoDatabaseFactory databaseFactory,
            ServiceContext services, AppCaches appCaches,
            IProfilingLogger profilingLogger,
            IPublishedUrlProvider publishedUrlProvider) : base(umbracoContextAccessor, databaseFactory, services, appCaches, profilingLogger, publishedUrlProvider)
        {
            _memberManager = memberManager;
            _memberService = memberService;
            _memberSignInManager = memberSignInManager;
            _coreScopeProvider = coreScopeProvider;
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [ValidateUmbracoFormRouteString]
        public async Task<IActionResult> HandleRegisterMember([Bind(Prefix = "registerModel")] RegisterModel model)
        {
            if (ModelState.IsValid == false)
            {
                return CurrentUmbracoPage();
            }

            MergeRouteValuesToModel(model);

            IdentityResult result = await RegisterMemberAsync(model);
            if (result.Succeeded)
            {
                TempData["FormSuccess"] = true;


                if (model.RedirectUrl.IsNullOrWhiteSpace() == false)
                {
                    return Redirect(model.RedirectUrl!);
                }


                return RedirectToCurrentUmbracoPage();
            }

            AddErrors(result);
            return CurrentUmbracoPage();
        }

        //Merging route values to model
        private void MergeRouteValuesToModel(RegisterModel model)
        {
            if (RouteData.Values.TryGetValue(nameof(RegisterModel.RedirectUrl), out var redirectUrl) && redirectUrl != null)
            {
                model.RedirectUrl = redirectUrl.ToString();
            }

            if (RouteData.Values.TryGetValue(nameof(RegisterModel.MemberTypeAlias), out var memberTypeAlias) &&
                memberTypeAlias != null)
            {
                model.MemberTypeAlias = memberTypeAlias.ToString()!;
            }

            if (RouteData.Values.TryGetValue(nameof(RegisterModel.UsernameIsEmail), out var usernameIsEmail) &&
                usernameIsEmail != null)
            {
                model.UsernameIsEmail = usernameIsEmail.ToString() == "True";
            }
        }

        //error method
        private void AddErrors(IdentityResult result)
        {
            foreach (IdentityError? error in result.Errors)
            {
                ModelState.AddModelError("registerModel", error.Description);
            }
        }


        // helper Method to assign a MemberGroup to a member.
        private void AssignMemberGroup(string email, string group)
        {
            try
            {
                _memberService.AssignRole(email, group);
            }
            catch (Exception ex)
            {
                // exception
            }

        }

        private async Task<IdentityResult> RegisterMemberAsync(RegisterModel model, bool logMemberIn = true)
        {
            using ICoreScope scope = _coreScopeProvider.CreateCoreScope(autoComplete: true);


            if (string.IsNullOrEmpty(model.Name) && string.IsNullOrEmpty(model.Email) == false)
            {
                model.Name = model.Email;
            }

            model.Username = model.UsernameIsEmail || model.Username == null ? model.Email : model.Username;

            var identityUser =
                MemberIdentityUser.CreateNew(model.Username, model.Email, model.MemberTypeAlias, true, model.Name);
            IdentityResult identityResult = await _memberManager.CreateAsync(
                identityUser,
                model.Password);

            if (identityResult.Succeeded)
            {

                IMember? member = _memberService.GetByKey(identityUser.Key);
                if (member == null)
                {

                    throw new InvalidOperationException($"Could not find a member with key: {member?.Key}.");
                }

                foreach (MemberPropertyModel property in model.MemberProperties.Where(p => p.Value != null).Where(property => member.Properties.Contains(property.Alias)))
                {
                    member.Properties[property.Alias]?.SetValue(property.Value);
                }

                //Before we save the member we make sure to assign the group, for this the "Group" must exist in the backoffice.
                string memberGroup = "Authorized Group";
                AssignMemberGroup(model.Email, memberGroup);

                _memberService.Save(member);

                if (logMemberIn)
                {
                    await _memberSignInManager.SignInAsync(identityUser, false);
                }
            }
            return identityResult;
        }

        // changing member password
        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangingPasswordModel model)
        {
            var token = Request.Query["token"];
            var passwordvalid = _memberManager.ValidatePasswordAsync(model.NewPassword).Result;
            if (passwordvalid.Succeeded)
            {
                try
                {
                    var member = _memberManager.GetCurrentMemberAsync().Result;
                    var changePasswordResult =
                        await _memberManager.ChangePasswordAsync(member, model.OldPassword, model.NewPassword);
                    if (changePasswordResult.Succeeded)
                    {
                        TempData["ValidationSuccess"] = "success";
                    }
                    else
                    {
                        foreach (var identityError in changePasswordResult.Errors)
                        {
                            TempData["ValidationError"] += identityError.Description;
                        }
                    }

                }
                catch (Exception e)
                {
                    TempData["ValidationError"] = e.Message;
                }
            }
            else
            {
                TempData["ValidationError"] = passwordvalid.Errors.ToString();
            }

            return CurrentUmbracoPage();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(string email,string token)
        {
            try
            {
                var identityUser = await _memberManager.FindByEmailAsync(email);
                
                
                //generating token and sending to the email

                if (identityUser != null)
                {
                    token = await _memberManager.GeneratePasswordResetTokenAsync(identityUser);
                    var encodeToken = WebUtility.UrlEncode(token);
                    var MailSetting = _configuration.GetSection("MailSetting");
                    MailMessage message = new MailMessage();
                    message.From = new MailAddress($"{MailSetting.GetSection("SenderEmail").Value}");
                    message.To.Add(new MailAddress(email));
                    message.Subject = "Testing";
                    var http = _httpContextAccessor.HttpContext.Request.Scheme;
                    var host = _httpContextAccessor.HttpContext.Request.Host.ToString();
                    var link = $"{http}://{host}/resetforgotpassword/?token={encodeToken}&&userid={identityUser.Id}";
                    message.Body = $"Click the link below to reset the password :</br> <a href={link}> Click Here </a>";

                    SmtpClient smtp = new SmtpClient();
                    smtp.Host = $"{MailSetting.GetSection("Server").Value}";
                    smtp.Port = Convert.ToInt32(MailSetting.GetSection("Port").Value);

                    smtp.UseDefaultCredentials = false;
                    smtp.Credentials = new System.Net.NetworkCredential($"{MailSetting.GetSection("SenderEmail").Value}", $"{MailSetting.GetSection("Password").Value}");
                    smtp.EnableSsl = true;
                    smtp.Send(message);
                    smtp.Dispose();

                }
            }

            catch (Exception e)
            {
                return null;
            }

            return CurrentUmbracoPage();
        }

        [HttpPost]
        public async Task<IActionResult> ResetForgotPassword(string newpassword)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            var queryString = httpContext.Request.QueryString.ToString();
            var queryParameters = HttpUtility.ParseQueryString(queryString);

            var TokenId =queryParameters["token"];
            var UserId = WebUtility.UrlDecode(queryParameters["userid"]);

            var member = await _memberManager.FindByIdAsync(UserId);
            if (member != null)
            {
                var result = await _memberManager.ResetPasswordAsync(member, TokenId, newpassword);
                if (result.Succeeded)
                {
                    return Redirect("/about");
                }
            }
            return CurrentUmbracoPage();
        }
    }
}
