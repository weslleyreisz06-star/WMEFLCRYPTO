let socket;

function setupSocket() {
  if (socket) return;
  socket = io();

  socket.on("connect", () => {
    console.log("Socket conectado");
  });

  socket.on("connected", (d) => {
    console.log("server says:", d);
  });

  socket.on("prices", (data) => {
    // data: { "BTC": {price:..., change:... }, ... }
    // atualizar cards e tabela
    Object.keys(data).forEach(sym => {
      const info = data[sym];
      // atualizar card se existir
      const card = document.getElementById("card-" + sym);
      if (card) {
        const p = card.querySelector(".price");
        const c = card.querySelector(".change");
        if (p) p.innerText = formatBRL(info.price);
        if (c) c.innerText = formatChange(info.change);
        // cor
        if (info.change !== null && info.change !== undefined) {
          c.style.background = info.change < 0 ? "rgba(231,76,60,0.14)" : "rgba(47,208,111,0.10)";
        }
      }
      // atualizar row
      const row = document.getElementById("row-" + sym);
      if (row) {
        const tdPrice = row.querySelector(".td-price");
        const tdChange = row.querySelector(".td-change");
        if (tdPrice) tdPrice.innerText = "R$ " + formatBRL(info.price);
        if (tdChange) tdChange.innerText = (info.change ? info.change.toFixed(2) + "%" : "--");
      }
    });
  });

  socket.on("balance_update", (d) => {
    const b = document.getElementById("balance");
    const bd = document.getElementById("balance-display");
    if (b && d.balance !== undefined) b.innerText = "R$ " + Number(d.balance).toFixed(2);
    if (bd && d.balance !== undefined) bd.innerText = "R$ " + Number(d.balance).toFixed(2);
  });
}

function formatBRL(n) {
  if (n === null || n === undefined) return "--";
  return Number(n).toLocaleString('pt-BR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function formatChange(c) {
  if (c === null || c === undefined) return "--";
  return (c > 0 ? "+" : "") + c.toFixed(2) + "%";
}
