#nullable disable

using System;
using System.Collections.Generic;
using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Altinn.Platform.Storage.Filters;

/// <summary>
/// Authorizes callers by exact match of the client IP (rightmost X-Forwarded-For hop, else connection remote IP) against the configured safelist, denying when no IP can be determined or the safelist is empty.
/// </summary>
public class ClientIpCheckActionFilterAttribute : ActionFilterAttribute
{
    private HashSet<IPAddress> _safeList;

    /// <summary>
    /// List of valid ip addresses
    /// </summary>
    public string Safelist
    {
        set
        {
            _safeList = new HashSet<IPAddress>();
            if (value is null)
            {
                return;
            }

            foreach (
                string entry in value.Split(
                    ';',
                    StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries
                )
            )
            {
                if (IPAddress.TryParse(entry, out IPAddress ipAddress))
                {
                    _safeList.Add(ipAddress);
                }
            }
        }
    }

    /// <summary>
    /// Authorize from IP address.
    /// </summary>
    /// <param name="context">context</param>
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        string forwardedFor = context.HttpContext?.Request.Headers["X-Forwarded-For"].ToString();
        IPAddress clientIp = null;

        if (!string.IsNullOrEmpty(forwardedFor))
        {
            string[] forwardedForEntries = forwardedFor.Split(
                ',',
                StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries
            );

            if (
                forwardedForEntries.Length > 0
                && IPEndPoint.TryParse(forwardedForEntries[^1], out IPEndPoint endpoint)
            )
            {
                clientIp = endpoint.Address;
            }
        }
        else
        {
            clientIp = context.HttpContext?.Connection.RemoteIpAddress;
        }

        if (clientIp?.IsIPv4MappedToIPv6 == true)
        {
            clientIp = clientIp.MapToIPv4();
        }

        if (
            _safeList is null
            || _safeList.Count == 0
            || clientIp is null
            || !_safeList.Contains(clientIp)
        )
        {
            context.Result = new ForbidResult();
            return;
        }

        base.OnActionExecuting(context);
    }
}
