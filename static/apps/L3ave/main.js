import { dotnet } from './_framework/dotnet.js';

const loaderElement = document.getElementById('loader');
const playButtonElement = document.getElementById('play-button');
const canvasElement = document.getElementById('canvas');
const backgroundMusic = document.getElementById('background-music');

const showLoader = async () => {
    loaderElement.style.display = '';
};

const hideLoader = async () => {
    loaderElement.style.display = 'none';
};

const showPlayButton = async () => {
    playButtonElement.style.display = '';
};

const hidePlayButton = async () => {
    playButtonElement.style.display = 'none';
};

const playBackgroundMusic = async() => {
    backgroundMusic.play().catch(
        error => console.log("Music playing is blocked:", error)
    );
};

const stopBackgroundMusic = async() => {
    backgroundMusic.pause();
    backgroundMusic.currentTime = 0;
};

const loadRuntime = async () => {
    await showLoader();
    await dotnet.create();
    dotnet.instance.Module['canvas'] = canvasElement;
    await hideLoader();
};

const startGame = async () => {
    await hidePlayButton();
    await playBackgroundMusic();
    await dotnet.instance.runMain();
    await stopBackgroundMusic();
    await showPlayButton();
};

const main = async () => {
    playButtonElement.addEventListener('click', startGame);

    await hideLoader();
    await hidePlayButton();
    await loadRuntime();
    await showPlayButton();
};

addEventListener("DOMContentLoaded", _ => main());
