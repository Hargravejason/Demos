using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using System.Text.RegularExpressions;
using System.Reflection;
using System.Linq;

public class XssProtectionMiddleware
{
  private readonly RequestDelegate _next;

  public XssProtectionMiddleware(RequestDelegate next)
  {
    _next = next;
  }

  public async Task InvokeAsync(HttpContext context)
  {
    if (context.Request.Method == HttpMethods.Post || context.Request.Method == HttpMethods.Put)
    {
      var form = await context.Request.ReadFormAsync();

      foreach (var field in form)
      {
        string key = field.Key;
        string value = field.Value;

        // Check for attributes based on the controller or request scope
        bool allowHtml = HasAttribute(context, "AllowHTML");
        bool allowScript = HasAttribute(context, "AllowScript");
        bool doNotValidate = HasAttribute(context, "DoNotValidate");

        if (!doNotValidate)
        {
          if (!allowHtml && ContainsHtml(value))
          {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("HTML content not allowed.");
            return;
          }

          if (!allowScript && ContainsScript(value))
          {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Script content not allowed.");
            return;
          }
        }
      }
    }

    await _next(context);
  }

  private bool ContainsHtml(string input)
  {
    return Regex.IsMatch(input, @"<.*?>");
  }

  private bool ContainsScript(string input)
  {
    return Regex.IsMatch(input, @"<script.*?>.*?</script>", RegexOptions.IgnoreCase);
  }

  private bool HasAttribute(HttpContext context, string attributeName)
  {
    var endpoint = context.GetEndpoint();
    if (endpoint != null)
    {
      var attributes = endpoint.Metadata
                               .OfType<Attribute>()
                               .Select(attr => attr.GetType().Name);
      return attributes.Contains(attributeName);
    }
    return false;
  }
}