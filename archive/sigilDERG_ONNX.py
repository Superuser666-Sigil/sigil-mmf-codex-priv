#!/usr/bin/env python
"""
unified_sigil_trainer_v6.py

Trains and exports an ONNX student model with enhanced relational reasoning
and teacher–student distillation support. This version is built to handle
rich, multi-dimensional data—such as that gathered by integrating rust-crate-pipeline
with Crawl4AI.

Key features:
  - Dynamic feature selection via a --feature_cols argument.
  - Two architecture variants: a simple “flat” MLP and a relational variant that processes
    feature-by-feature tokens through a lightweight Transformer encoder.
  - Optional teacher–student distillation: if a teacher_logits file is provided, a KD loss is applied.
  - Manifest generation and optional GPG signing for deployment.

Usage examples:
  python unified_sigil_trainer_v6.py --mode trust --csv enriched_data.csv --onnx trust_model.onnx \
       --feature_cols x0,x1,x2,x3,x4,x5,x6,x7
  python unified_sigil_trainer_v6.py --mode classify --csv enriched_classify.csv --onnx classify_model.onnx \
       --feature_cols f1,f2,f3,f4,f5,f6,f7,f8,f9 --relational --teacher_logits teacher_logits.npy --kd_weight 0.5 --sign
"""

import argparse, csv, hashlib, json, pathlib, subprocess
from datetime import datetime

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.utils.data as td
from tqdm import tqdm

# ----------------- Global Hyperparameters -----------------
HIDDEN_DIM = 32         # Increase hidden dimensions if richer data permits
NUM_CLASSES = 3         # For classification mode (otherwise regression/trust)
EPOCHS = 25
BATCH = 128
LEARNING_RT = 1e-3
VERSION = "v6-unified"

# ----------------- Model Definitions -----------------

# Flat MLP architecture that uses dynamic input dimensions.
class UnifiedSigilNet(nn.Module):
    def __init__(self, input_dim, mode="trust"):
        super().__init__()
        self.mode = mode
        self.input_dim = input_dim
        self.norm = nn.LayerNorm(input_dim)
        self.fc1 = nn.Linear(input_dim, HIDDEN_DIM)
        self.fc2 = nn.Linear(HIDDEN_DIM, HIDDEN_DIM if mode == "classify" else 1)
        self.out = nn.Linear(HIDDEN_DIM, NUM_CLASSES) if mode == "classify" else nn.Identity()

    def forward(self, x):
        x = self.norm(x)
        x = F.gelu(self.fc1(x))
        x = F.dropout(x, p=0.10, training=self.training)
        x = F.gelu(self.fc2(x))
        if self.mode == "trust":
            score = torch.sigmoid(x)
            # A simple proxy for confidence
            confidence = (score - 0.5).abs() * 2
            return score, confidence
        else:
            return self.out(x)

# Relational variant that treats each input feature as a token.
class RelationalSigilNet(nn.Module):
    def __init__(self, input_dim, mode="trust"):
        super().__init__()
        self.mode = mode
        self.input_dim = input_dim
        # Each feature is projected into a token embedding of size HIDDEN_DIM.
        self.token_embed_dim = HIDDEN_DIM
        self.feature_proj = nn.Linear(1, self.token_embed_dim)
        # Learnable positional embeddings (one per input feature)
        self.positional = nn.Parameter(torch.zeros(input_dim, self.token_embed_dim))
        # Single-layer Transformer encoder with 1 attention head.
        self.transformer = nn.TransformerEncoderLayer(
            d_model=self.token_embed_dim, nhead=1, batch_first=True
        )
        # Pool across tokens and process the aggregated representation.
        self.fc = nn.Sequential(
            nn.LayerNorm(self.token_embed_dim),
            nn.Linear(self.token_embed_dim, HIDDEN_DIM),
            nn.GELU(),
            nn.Dropout(0.10),
            nn.Linear(HIDDEN_DIM, HIDDEN_DIM if mode == "classify" else 1)
        )
        self.out = nn.Linear(HIDDEN_DIM, NUM_CLASSES) if mode == "classify" else nn.Identity()

    def forward(self, x):
        # x shape: (batch, input_dim)
        x = x.unsqueeze(-1)  # Now shape: (batch, input_dim, 1)
        x = self.feature_proj(x)  # Shape: (batch, input_dim, token_embed_dim)
        x = x + self.positional  # Apply positional bias
        x = self.transformer(x)  # Process relationally across features
        x = x.mean(dim=1)       # Pool features (mean pooling)
        x = self.fc(x)
        if self.mode == "trust":
            score = torch.sigmoid(x)
            confidence = (score - 0.5).abs() * 2
            return score, confidence
        else:
            return self.out(x)

# ----------------- Data Loading -----------------

def load_csv(path, feature_cols, mode, teacher_logits_file=None):
    """
    Load a CSV file and only use the columns specified in feature_cols.
    The CSV should also have a target column "y" for training.
    If teacher_logits_file is provided, it is assumed to be an npy file where the
    i-th row corresponds to the enriched target from the teacher.
    """
    xs, ys, teacher_targets = [], [], []
    teacher_all = None
    if teacher_logits_file:
        teacher_all = np.load(teacher_logits_file)
    with open(path, newline='') as fh:
        rdr = csv.DictReader(fh)
        for i, row in enumerate(rdr):
            try:
                # Dynamically gather features from the specified columns.
                vec = [float(row[col]) for col in feature_cols if col in row]
            except Exception as ex:
                continue
            # Skip rows with missing data.
            if any(np.isnan(vec)):
                continue
            xs.append(vec)
            # The target must be in the "y" column.
            ys.append(float(row["y"]) if mode == "trust" else int(row["y"]))
            if teacher_all is not None:
                teacher_targets.append(teacher_all[i])
    xs = np.array(xs, dtype=np.float32)
    # Normalize features columnwise.
    xs_min = xs.min(axis=0)
    xs_max = xs.max(axis=0)
    xs_norm = (xs - xs_min) / (xs_max - xs_min + 1e-8)
    x = torch.tensor(xs_norm, dtype=torch.float32)
    if mode == "trust":
        y = torch.tensor(ys, dtype=torch.float32)
    else:
        y = torch.tensor(ys, dtype=torch.long)
    if teacher_all is not None:
        teacher_tensor = torch.tensor(np.array(teacher_targets), dtype=torch.float32)
        return td.TensorDataset(x, y, teacher_tensor)
    else:
        return td.TensorDataset(x, y)

# ----------------- Training Loop -----------------

def train(model, loader, mode, kd_weight=0.0):
    """
    Training loop with support for teacher–student distillation.
    If kd_weight > 0, expect the loader to return (x, y, teacher_target).
    """
    base_loss_fn = nn.BCELoss() if mode == "trust" else nn.CrossEntropyLoss()
    kd_loss_fn = nn.MSELoss() if mode == "trust" else nn.KLDivLoss(reduction="batchmean")
    
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RT)
    for epoch in range(EPOCHS):
        model.train()
        running_loss = 0.0
        pbar = tqdm(loader, desc=f"Epoch {epoch+1}/{EPOCHS}")
        for batch in pbar:
            optimizer.zero_grad()
            if len(batch) == 3:
                xb, yb, teacher_target = batch
            else:
                xb, yb = batch
                teacher_target = None
            out = model(xb)
            if mode == "trust":
                # For trust mode, use the predicted score.
                pred = out[0].squeeze(1)
            else:
                pred = out
            loss = base_loss_fn(pred, yb)
            if teacher_target is not None and kd_weight > 0:
                if mode == "trust":
                    kd_loss = kd_loss_fn(pred, teacher_target)
                else:
                    kd_loss = kd_loss_fn(F.log_softmax(pred, dim=-1), F.softmax(teacher_target, dim=-1))
                loss = (1 - kd_weight) * loss + kd_weight * kd_loss
            loss.backward()
            optimizer.step()
            running_loss += loss.item()
            pbar.set_postfix({"loss": running_loss / (pbar.n + 1)})
    return model

# ----------------- ONNX Export -----------------

def export_onnx(model, path, mode):
    model.eval()
    dummy = torch.randn(1, model.input_dim)
    if mode == "trust":
        output_names = ["score", "confidence"]
    else:
        output_names = ["logits"]
    torch.onnx.export(
        model,
        dummy,
        path,
        input_names=["x"],
        output_names=output_names,
        dynamic_axes={"x": {0: "batch_size"}},
        opset_version=17,
    )

# ----------------- Manifest + Signing -----------------

def hash_file(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def write_manifest(path, sha, mode, input_dim, hidden_dim, classes, version):
    manifest = {
        pathlib.Path(path).name: sha,
        "version": version,
        "mode": mode,
        "input_dim": input_dim,
        "hidden_dim": hidden_dim,
        "classes": classes,
        "timestamp": datetime.now().isoformat(),
    }
    manifest_path = pathlib.Path(path).with_name("model_manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

def sign_model(path):
    try:
        subprocess.run(["gpg", "--detach-sign", "--armor", path], check=True)
        print("GPG signature created.")
    except Exception as e:
        print("GPG signing failed:", e)

# ----------------- Main -----------------

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["trust", "classify"], required=True, help="Operation mode")
    ap.add_argument("--csv", required=True, help="CSV file with enriched training data")
    ap.add_argument("--onnx", required=True, help="Output ONNX model file")
    ap.add_argument("--feature_cols", required=False, default="", help="Comma-separated feature column names (e.g., x0,x1,x2)")
    ap.add_argument("--sign", action="store_true", help="GPG-sign the exported ONNX model")
    ap.add_argument("--relational", action="store_true", help="Use the relational transformer variant")
    ap.add_argument("--teacher_logits", default=None, help="Optional teacher logits file (npy)")
    ap.add_argument("--kd_weight", type=float, default=0.0, help="Weight for KD loss (0 disables distillation)")
    args = ap.parse_args()

    # Determine features: either use provided list or (as a fallback) default to a small set.
    if args.feature_cols:
        feature_cols = [col.strip() for col in args.feature_cols.split(",")]
    else:
        # Defaults – adjust as needed if enrichment adds more columns.
        feature_cols = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
    
    input_dim = len(feature_cols)
    
    # Choose the student model architecture.
    if args.relational:
        model = RelationalSigilNet(input_dim=input_dim, mode=args.mode)
    else:
        model = UnifiedSigilNet(input_dim=input_dim, mode=args.mode)
    
    # Load the dataset (with teacher logits if provided).
    dataset = load_csv(args.csv, feature_cols, args.mode, teacher_logits_file=args.teacher_logits)
    loader = td.DataLoader(dataset, batch_size=BATCH, shuffle=True)
    
    # Train the model.
    model = train(model, loader, args.mode, kd_weight=args.kd_weight)
    
    # Export the trained model to ONNX.
    export_onnx(model, args.onnx, args.mode)
    sha = hash_file(args.onnx)
    classes = NUM_CLASSES if args.mode == "classify" else 1
    write_manifest(args.onnx, sha, args.mode, input_dim, HIDDEN_DIM, classes, VERSION)
    if args.sign:
        sign_model(args.onnx)
    print(f"Model and manifest ready for mode: {args.mode}, using features: {feature_cols}")