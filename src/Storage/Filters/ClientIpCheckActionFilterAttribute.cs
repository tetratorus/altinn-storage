#nullable disable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Altinn.Platform.Storage.Filters;

/// <summary>
/// Restricts access to the connecting client's IP address. The address is taken from
/// <see cref="Microsoft.AspNetCore.Http.ConnectionInfo.RemoteIpAddress"/>, which the forwarded
/// headers middleware populates from <c>X-Forwarded-For</c> only when the request arrives from a
/// configured trusted proxy. Client-supplied headers are never consulted directly.
/// </summary>
public class ClientIpCheckActionFilterAttribute : ActionFilterAttribute
{
    private readonly List<IPAddress> _safeAddresses = [];
    private readonly List<IPNetwork> _safeNetworks = [];

    /// <summary>
    /// Semicolon separated list of allowed IP addresses or CIDR networks. An empty list denies all requests.
    /// </summary>
    public string Safelist
    {
        set
        {
            _safeAddresses.Clear();
            _safeNetworks.Clear();
            foreach (
                string entry in (value ?? string.Empty).Split(
                    ';',
                    StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries
                )
            )
            {
                if (IPAddress.TryParse(entry, out IPAddress address))
                {
                    _safeAddresses.Add(Normalize(address));
                }
                else if (IPNetwork.TryParse(entry, out IPNetwork network))
                {
                    _safeNetworks.Add(network);
                }
                else
                {
                    throw new ArgumentException(
                        $"Invalid IP address or network in safelist: '{entry}'",
                        nameof(Safelist)
                    );
                }
            }
        }
    }

    /// <summary>
    /// Authorize from ip address
    /// </summary>
    /// <param name="context">context</param>
    public override void OnActionExecuting(ActionExecutingContext context)
    {
        IPAddress remoteIp = context.HttpContext?.Connection?.RemoteIpAddress;

        if (remoteIp == null || !IsAllowed(Normalize(remoteIp)))
        {
            context.Result = new ForbidResult();
            return;
        }

        base.OnActionExecuting(context);
    }

    private bool IsAllowed(IPAddress address)
    {
        return _safeAddresses.Contains(address)
            || _safeNetworks.Any(network => network.Contains(address));
    }

    private static IPAddress Normalize(IPAddress address)
    {
        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    }
}
