#nullable disable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Primitives;

namespace Altinn.Platform.Storage.Filters;

/// <summary>
/// Restricts access to an action to a configured list of client IP addresses.
/// The filter fails closed: an empty or unparsable safelist rejects every request.
/// </summary>
public class ClientIpCheckActionFilterAttribute : ActionFilterAttribute
{
    private HashSet<IPAddress> _safeList = new();

    /// <summary>
    /// Semicolon separated list of valid ip addresses
    /// </summary>
    public string Safelist
    {
        set
        {
            _safeList = (value ?? string.Empty)
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(ParseAddress)
                .Where(address => address != null)
                .ToHashSet();
        }
    }

    /// <summary>
    /// Authorize from ip address
    /// </summary>
    /// <param name="context">context</param>
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        IPAddress clientAddress = GetClientAddress(context.HttpContext);

        if (_safeList.Count == 0 || clientAddress == null || !_safeList.Contains(clientAddress))
        {
            context.Result = new ForbidResult();
            return;
        }

        base.OnActionExecuting(context);
    }

    /// <summary>
    /// Resolves the client address. When a reverse proxy has appended the caller address to
    /// X-Forwarded-For, the rightmost entry is the address seen by the proxy closest to this
    /// service; otherwise the address of the direct connection is used.
    /// </summary>
    private static IPAddress GetClientAddress(HttpContext httpContext)
    {
        if (httpContext == null)
        {
            return null;
        }

        StringValues forwardedFor = httpContext.Request.Headers["X-Forwarded-For"];
        string lastForwarded = forwardedFor
            .SelectMany(value => (value ?? string.Empty).Split(','))
            .Select(value => value.Trim())
            .LastOrDefault(value => value.Length > 0);

        if (lastForwarded != null)
        {
            return ParseAddress(lastForwarded);
        }

        return Normalize(httpContext.Connection.RemoteIpAddress);
    }

    private static IPAddress ParseAddress(string value)
    {
        if (IPEndPoint.TryParse(value, out IPEndPoint endPoint))
        {
            return Normalize(endPoint.Address);
        }

        return IPAddress.TryParse(value, out IPAddress address) ? Normalize(address) : null;
    }

    private static IPAddress Normalize(IPAddress address)
    {
        if (address == null)
        {
            return null;
        }

        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    }
}
