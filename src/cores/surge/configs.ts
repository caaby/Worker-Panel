import { getSettings } from '@settings';
import {
    generateRemark,
    generateWsPath,
    getConfigAddresses,
    isHttps,
    selectSniHost
} from '@utils';

export async function getSurgeNodeList(): Promise<Response> {
    const {
        ports,
        customDomain,
        trPass,
        mainDomain,
        upstreamParams: { upstreamServer, upstreamPort }
    } = getSettings();

    const domains = [mainDomain].concatIf(!!customDomain, customDomain);
    const lines: string[] = [];
    let proxyIndex = 1;

    for (const domain of domains) {
        const totalPorts = ports.filter(port => domain.endsWith('workers.dev') || isHttps(port));
        const addrs = await getConfigAddresses(domain, false);
        if (upstreamServer && upstreamPort) {
            totalPorts.unshift(upstreamPort);
            addrs.unshift(upstreamServer);
        }

        for (const port of totalPorts) {
            for (const addr of addrs) {
                if ((port === upstreamPort) !== (addr === upstreamServer)) continue;

                const { sni, host } = selectSniHost(addr, domain);
                const isTLS = isHttps(port) || addr === upstreamServer;
                const server = normalizeServer(addr);

                if (isTLS) {
                    const remark = generateRemark(proxyIndex, port, addr, _TR_, domain, false, false);
                    lines.push(buildTrojanLine(remark, server, port, trPass, host, sni));
                }

                proxyIndex++;
            }
        }
    }

    return new Response(lines.join('\n'), {
        status: 200,
        headers: {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Disposition': `attachment; filename=${_project_SM_}-raw-surge-node-list.conf`,
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET',
            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma': 'no-cache',
            'Expires': '0'
        }
    });
}

function buildTrojanLine(
    remark: string,
    server: string,
    port: number,
    password: string,
    host: string,
    sni: string
): string {
    return [
        `${remark} = ${_TR_}`,
        server,
        port,
        `password=${password}`,
        `sni=${sni}`,
        'ws=true',
        `ws-path=${generateWsPath(_TR_)}?ed=2560`,
        `ws-headers=Host:${host}`
    ].join(', ');
}

function normalizeServer(address: string): string {
    return address.replace(/^\[|\]$/g, '');
}
