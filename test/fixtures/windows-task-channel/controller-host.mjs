import { pathToFileURL } from 'node:url';
setTimeout(() => process.exit(0), 45000);
const { createTaskChannel } = await import(pathToFileURL(process.env.OWNED_CHANNEL_MODULE).href);
process.once('message', async options => {
  try {
    const channel = await createTaskChannel(options);
    process.send({ type: 'host-ready', channel: {
      endpoint: channel.endpoint, manifestPath: channel.manifestPath, guardIdentity: channel.guardIdentity,
      controllerIdentity: channel.controllerIdentity,
    } });
    channel.awaitWorker().then(peer => process.send({ type: 'host-peer', peer }), () => {});
    process.on('message', message => { if (message.action === 'exit') process.exit(0); });
  } catch (error) { process.send({ type: 'host-error', message: error.message, guardIdentity: error.guardIdentity }); }
});
